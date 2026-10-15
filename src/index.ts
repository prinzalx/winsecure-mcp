#!/usr/bin/env node
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";

import { loadConfig } from "./config.js";
import { ALL_TOOLS } from "./modules/index.js";
import { openStore } from "./store.js";
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

async function main(): Promise<void> {
  const config = loadConfig();
  const store = openStore(config.settings.dataDir);
  const http = createHttp(`${config.settings.dataDir}/cache`, config.settings.httpTimeoutMs);

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
      ((args: Record<string, unknown>) => invoke(tool, args ?? {}, ctx)) as never,
    );
  }

  const transport = new StdioServerTransport();
  await server.connect(transport);

  // The client capabilities are only known after the handshake, so sampling is decided per session
  // here rather than at construction time.
  server.server.oninitialized = () => {
    const caps = server.server.getClientCapabilities();
    samplingActive = Boolean(caps?.sampling);
    process.stderr.write(
      `  client capabilities: sampling=${String(Boolean(caps?.sampling))}, elicitation=${String(Boolean(caps?.elicitation))}\n`,
    );
  };

  process.stderr.write(
    [
      "",
      "  winsecure-mcp",
      `  version         v${VERSION}`,
      `  data directory  ${config.settings.dataDir}`,
      `  store file      ${store.path}`,
      `  MCP transport   stdio — this terminal stays attached to the agent`,
      "",
    ].join("\n"),
  );
}

/**
 * Runs a tool with input validation and error capture.
 *
 * A handler that throws is turned into a failed result rather than an MCP protocol error, so a
 * client sees the message and the server keeps its session.
 */
async function invoke(tool: ToolDefinition, args: Record<string, unknown>, ctx: ToolContext) {
  const parsed = tool.input.safeParse(args ?? {});
  if (!parsed.success) {
    const message = parsed.error.issues.map((i) => `${i.path.join(".") || "input"}: ${i.message}`).join("; ");
    return fail(`Invalid input for ${tool.name} — ${message}`);
  }
  const started = Date.now();
  try {
    const result = await tool.handler(parsed.data as Record<string, unknown>, ctx);
    const ms = Date.now() - started;
    process.stderr.write(`  ${result.isError ? "err " : "ok  "} ${tool.name} ${String(ms)} ms\n`);
    return result;
  } catch (cause) {
    const message = cause instanceof Error ? cause.message : String(cause);
    process.stderr.write(`  err  ${tool.name} threw: ${message}\n`);
    return fail(`${tool.name} threw: ${message}`);
  }
}

main().catch((cause: unknown) => {
  process.stderr.write(`winsecure-mcp failed to start: ${String(cause instanceof Error ? cause.message : cause)}\n`);
  process.exitCode = 1;
});


