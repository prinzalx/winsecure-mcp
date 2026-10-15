#!/usr/bin/env node
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { createServer, type IncomingMessage, type ServerResponse } from "node:http";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";

import { ARGS, loadConfig } from "./config.js";
import { computeState, createActivity } from "./dashboard.js";
import { ALL_TOOLS, TOOLS_BY_NAME } from "./modules/index.js";
import { openStore, storeExists } from "./store.js";
import type { ToolContext, ToolDefinition } from "./types.js";
import { fail } from "./utils/result.js";
import { createHttp } from "./utils/net.js";

/**
 * Read from package.json so a release bump has exactly one place to be updated. The file sits next
 * to dist/ in every install, including a global npm one.
 */
const VERSION = (() => {
  try {
    const raw = readFileSync(fileURLToPath(new URL("../package.json", import.meta.url)), "utf8");
    return String((JSON.parse(raw) as { version?: string }).version ?? "0.0.0");
  } catch {
    return "0.0.0";
  }
})();

const BANNER = String.raw`
██╗   ██╗███╗   ██╗ █████╗ ███████╗███████╗██╗   ██╗██████╗ ███████╗
██║   ██║████╗  ██║██╔══██╗██╔════╝██╔════╝██║   ██║██╔══██╗██╔════╝
██║   ██║██╔██╗ ██║███████║█████╗  █████╗  ██║   ██║██████╔╝█████╗
██║   ██║██║╚██╗██║██╔══██║██╔══╝  ██╔══╝  ██║   ██║██╔══██╗██╔══╝
╚██████╔╝██║ ╚████║██║  ██║███████╗███████╗╚██████╔╝██║  ██║███████╗
 ╚═════╝ ╚═╝  ╚═══╝╚═╝  ╚═╝╚══════╝╚══════╝ ╚═════╝ ╚═╝  ╚═╝╚══════╝
`;

const HELP = `winsecure-mcp — Windows CVE inventory MCP server

usage: node dist/index.js [options]

  --port <n>     dashboard port (default 8788, env WSMD_PORT)
  --no-web       do not start the dashboard; stdio only (env WSMD_NO_WEB=1)
  --config <p>   path to the JSON config file (env WSMD_CONFIG)
  --data-dir <p> directory for store, caches and config (env WSMD_DATA_DIR)
  --help         show this text
`;

/**
 * The MCP server for the whole tool set.
 *
 * The approval gate of the winadmin model is deliberately *not* copied here: §5 says every write
 * of this server goes into its own files, so no tool can damage the system and no gate is needed.
 * The one capability that matters instead is sampling, which decides how `assess_todo` answers.
 */
function zodShape(tool: ToolDefinition): Record<string, unknown> {
  return (tool.input as unknown as { shape?: Record<string, unknown> }).shape ?? {};
}

/** Set in main() so the dashboard endpoints can report what the attached stdio client can do. */
let attachedClientSampling: boolean | null = null;

async function main(): Promise<void> {
  if (ARGS.get("help") === true) {
    process.stdout.write(HELP);
    process.exit(0);
  }

  const config = loadConfig();
  const store = openStore(config.settings.dataDir);
  const http = createHttp(`${config.settings.dataDir}/cache`, config.settings.httpTimeoutMs);
  const activity = createActivity();

  const server = new McpServer(
    { name: "winsecure-mcp", version: VERSION },
    {
      instructions:
        "Windows software inventory against the CVE sources. scan_inventory reads the machine, check_cves fills the " +
        "to-do list, list_todos shows it, assess_todo rates the patch effort. Nothing here changes the system: the " +
        "server only ever writes its own JSON files.",
    },
  );

  let samplingActive = false;

  const ctx: ToolContext = {
    config,
    store,
    http,
    clientSampling: () => samplingActive,
    async sample(prompt: string) {
      if (!samplingActive) return null;
      try {
        const res = await server.server.createMessage({
          messages: [{ role: "user", content: { type: "text", text: prompt } }],
          maxTokens: 512,
        });
        if (res.content.type !== "text") return null;
        return { text: res.content.text };
      } catch (cause) {
        process.stderr.write(`  sampling failed: ${String(cause instanceof Error ? cause.message : cause)}\n`);
        return null;
      }
    },
  };

  for (const tool of ALL_TOOLS) {
    server.registerTool(
      tool.name,
      { title: tool.title, description: tool.description, inputSchema: zodShape(tool) as never },
      ((args: Record<string, unknown>) => invoke(tool, args ?? {}, ctx, activity, "stdio")) as never,
    );
  }

  // The client capabilities are only known after the handshake, so sampling is decided per session
  // here rather than at construction time.
  server.server.oninitialized = () => {
    const caps = server.server.getClientCapabilities();
    samplingActive = Boolean(caps?.sampling);
    attachedClientSampling = samplingActive;
    const client = server.server.getClientVersion();
    process.stderr.write(
      `  client connected: ${client?.name ?? "unknown"} ${client?.version ?? ""}` +
        ` — sampling ${String(Boolean(caps?.sampling))}, elicitation ${String(Boolean(caps?.elicitation))}\n`,
    );
  };

  // The dashboard is a second window onto the same process: it calls the very same tool handlers,
  // so it can never disagree with what an agent saw. stdio stays the MCP transport either way.
  const webDisabled = ARGS.get("no-web") === true || process.env.WSMD_NO_WEB === "1";
  const port = Number(ARGS.get("port") ?? process.env.WSMD_PORT ?? 8788);
  let webUrl: string | null = null;

  if (!webDisabled) {
    const web = createServer((req, res) => {
      void handleWeb(req, res, ctx, store, activity);
    });
    // An unhandled error on a listening socket would take the whole MCP server down; the dashboard
    // is optional by design, so a taken port only costs the dashboard.
    web.on("error", (cause: Error) => {
      process.stderr.write(`  dashboard disabled: ${cause.message}\n`);
      webUrl = null;
    });
    try {
      await new Promise<void>((resolve, reject) => {
        web.once("error", reject);
        web.listen(port, "127.0.0.1", () => resolve());
      });
      webUrl = `http://127.0.0.1:${String(port)}`;
    } catch (cause) {
      process.stderr.write(`  dashboard disabled: ${String(cause instanceof Error ? cause.message : cause)}\n`);
    }
  }

  const transport = new StdioServerTransport();
  await server.connect(transport);

  process.stderr.write(`\n${BANNER}`);
  process.stderr.write(
    [
      `  version         v${VERSION}`,
      `  data directory  ${config.settings.dataDir}`,
      `  store file      ${store.path}`,
      webUrl === null ? "  dashboard       disabled (--no-web)" : `  dashboard       ${webUrl}`,
      `  MCP transport   stdio — this terminal stays attached to the agent`,
      "",
    ].join("\n"),
  );
}

/**
 * The dashboard HTTP surface: a state endpoint, a run endpoint and the static page.
 *
 * Binding stays on the loopback address, and the only writes possible through it are the server's
 * own tool writes, so nothing here needs an approval gate either.
 */
async function handleWeb(
  req: IncomingMessage,
  res: ServerResponse,
  ctx: ToolContext,
  store: ReturnType<typeof openStore>,
  activity: ReturnType<typeof createActivity>,
): Promise<void> {
  const url = new URL(req.url ?? "/", `http://${req.headers.host ?? "127.0.0.1"}`);

  const send = (status: number, body: unknown): void => {
    res.writeHead(status, { "content-type": "application/json" });
    res.end(JSON.stringify(body));
  };

  try {
    if (url.pathname === "/api/state") {
      const data = store.load();
      return send(200, computeState({
        version: VERSION,
        store: data,
        storeExists: storeExists(store),
        dataDir: ctx.config.settings.dataDir,
        storePath: store.path,
        tools: ALL_TOOLS,
        activity: activity.recent(20),
        clientSampling: attachedClientSampling,
      }));
    }

    if (url.pathname === "/api/run" && req.method === "POST") {
      const chunks: Buffer[] = [];
      for await (const chunk of req) chunks.push(chunk as Buffer);
      const raw = Buffer.concat(chunks).toString("utf8");
      const body = (raw ? JSON.parse(raw) : {}) as { tool?: unknown; args?: Record<string, unknown> };
      const tool = TOOLS_BY_NAME.get(String(body.tool ?? ""));
      if (!tool) return send(404, { error: `Unknown tool "${String(body.tool)}"` });
      // A dashboard scan/check runs with the same defaults as an agent call, through the same
      // handler and the same store, so both views stay consistent.
      const result = await invoke(tool, body.args ?? {}, ctx, activity, "web");
      return send(200, {
        ok: result.isError !== true,
        output: result.content.map((c) => ("text" in c ? c.text : "")).join("\n"),
      });
    }

    if (req.method === "GET") {
      res.writeHead(200, { "content-type": "text/html; charset=utf-8" });
      res.end(readFileSync(fileURLToPath(new URL("./webui.html", import.meta.url)), "utf8"));
      return;
    }

    return send(404, { error: `No route for ${url.pathname}` });
  } catch (cause) {
    send(500, { error: String(cause instanceof Error ? cause.message : cause) });
  }
}

/**
 * Runs a tool with input validation and error capture.
 *
 * A handler that throws is turned into a failed result rather than an MCP protocol error, so a
 * client sees the message and the server keeps its session.
 */
async function invoke(
  tool: ToolDefinition,
  args: Record<string, unknown>,
  ctx: ToolContext,
  activity?: ReturnType<typeof createActivity>,
  origin = "stdio",
) {
  const parsed = tool.input.safeParse(args ?? {});
  if (!parsed.success) {
    const message = parsed.error.issues.map((i) => `${i.path.join(".") || "input"}: ${i.message}`).join("; ");
    return fail(`Invalid input for ${tool.name} — ${message}`);
  }
  const started = Date.now();
  try {
    const result = await tool.handler(parsed.data as Record<string, unknown>, ctx);
    const ms = Date.now() - started;
    process.stderr.write(`  ${result.isError ? "err " : "ok  "} ${tool.name} (${origin}) ${String(ms)} ms\n`);
    activity?.add({
      at: new Date().toISOString(),
      tool: tool.name,
      ok: result.isError !== true,
      duration_ms: ms,
      origin,
      summary: result.content.map((c) => ("text" in c ? c.text : "")).join(" ").slice(0, 300),
    });
    return result;
  } catch (cause) {
    const message = cause instanceof Error ? cause.message : String(cause);
    process.stderr.write(`  err  ${tool.name} threw: ${message}\n`);
    activity?.add({ at: new Date().toISOString(), tool: tool.name, ok: false, duration_ms: Date.now() - started, origin, summary: message });
    return fail(`${tool.name} threw: ${message}`);
  }
}

main().catch((cause: unknown) => {
  process.stderr.write(`winsecure-mcp failed to start: ${String(cause instanceof Error ? cause.message : cause)}\n`);
  process.exitCode = 1;
});


