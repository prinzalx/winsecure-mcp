/**
 * Proves the HTTP transport: alongside stdio the server answers a real MCP session on /mcp, so a
 * client that connects by url (Hermes) works without spawning node. Like winadmin, one listener
 * carries /api/, /mcp and the dashboard; a bare GET on /mcp is an MCP error (406), not HTML.
 *
 * Usage: node scripts/http-test.mjs [port]
 */
const port = process.argv[2] ?? "8799";
const base = `http://127.0.0.1:${port}/mcp`;

const { spawn } = await import("node:child_process");
const server = spawn(process.execPath, ["dist/index.js", "--port", port], {
  cwd: process.cwd(),
  env: { ...process.env, WSMD_DATA_DIR: process.env.WSMD_DATA_DIR ?? ".wsmd-http-test-data" },
  // stdin must stay open: the server ends when its stdio client closes it, and "ignore" would look
  // like an immediate close.
  stdio: ["pipe", "pipe", "pipe"],
});
server.stderr.on("data", (c) => process.stderr.write(String(c)));

async function rpc(payload, sessionId, endpoint = base) {
  const headers = {
    Accept: "application/json, text/event-stream",
    "Content-Type": "application/json",
    "MCP-Protocol-Version": "2025-06-18",
  };
  if (sessionId) headers["mcp-session-id"] = sessionId;
  const res = await fetch(endpoint, { method: "POST", headers, body: JSON.stringify(payload) });
  const text = await res.text();
  if (!res.ok) throw new Error(`${payload.method} → HTTP ${String(res.status)}: ${text.slice(0, 200)}`);
  const payloadText = text.includes("data:") ? text.split("data:").slice(1).join("data:").trim() : text.trim();
  const contentType = res.headers.get("content-type") ?? "";
  if (contentType.includes("text/html")) throw new Error(`${payload.method} → HTML from ${endpoint} (routed to the dashboard, not MCP)`);
  return {
    contentType,
    sessionId: res.headers.get("mcp-session-id") ?? null,
    // A notification is answered with 202 and no body at all.
    body: payloadText === "" ? {} : JSON.parse(payloadText),
  };
}

const started = Date.now();
let up = false;
while (Date.now() - started < 20_000) {
  try {
    const init = await rpc({ jsonrpc: "2.0", id: 1, method: "initialize", params: {
      protocolVersion: "2025-06-18",
      capabilities: { sampling: {} },
      clientInfo: { name: "http-test", version: "0.0.0" },
    } });
    up = true;
    console.log(`initialize → ${String(init.body.result.serverInfo.name)} v${String(init.body.result.serverInfo.version)}, session ${String(init.sessionId).slice(0, 8)}`);

    const sid = init.sessionId;
    await rpc({ jsonrpc: "2.0", method: "notifications/initialized" }, sid);
    const tools = await rpc({ jsonrpc: "2.0", id: 2, method: "tools/list" }, sid);
    const names = tools.body.result.tools.map((t) => t.name);
    console.log(`tools/list → ${String(names.length)} tools: ${names.join(", ")}`);
    if (names.length < 8) throw new Error("expected the full tool set over HTTP");

    const listed = await rpc({ jsonrpc: "2.0", id: 3, method: "tools/call", params: { name: "list_todos", arguments: {} } }, sid);
    console.log(`tools/call list_todos → ${String(listed.body.result.content[0].text).split("\n")[0].slice(0, 120)}`);

    const resources = await rpc({ jsonrpc: "2.0", id: 4, method: "resources/list" }, sid);
    console.log(`resources/list → ${String(resources.body.result.resources.length)} resource(s)`);

    const deleted = await fetch(base, {
      method: "DELETE",
      headers: { Accept: "application/json, text/event-stream", "mcp-session-id": sid, "MCP-Protocol-Version": "2025-06-18" },
    });
    console.log(`DELETE → HTTP ${String(deleted.status)}`);

    // Regression guard: a trailing slash must reach the MCP transport and not fall through to the
    // dashboard (which would answer HTML). Done last, so the main session stays untouched.
    const slashed = await rpc({ jsonrpc: "2.0", id: 5, method: "initialize", params: {
      protocolVersion: "2025-06-18",
      capabilities: {},
      clientInfo: { name: "http-test-slash", version: "0.0.0" },
    } }, undefined, `${base}/`);
    if (!slashed.sessionId) throw new Error("/mcp/ did not return a session id");
    console.log(`/mcp/ → ${slashed.contentType.split(";")[0]}, session ${String(slashed.sessionId).slice(0, 8)}`);

    // A bare GET without an Accept header is not a browser and not an MCP client: the transport
    // must answer its 406 JSON here, exactly like winadmin — never the dashboard HTML.
    const bare = await fetch(base, { headers: {} });
    const bareText = await bare.text();
    if (bare.status !== 406 || !bareText.includes("Not Acceptable")) throw new Error(`bare GET /mcp → HTTP ${String(bare.status)}: ${bareText.slice(0, 80)}`);
    console.log(`bare GET /mcp → HTTP ${String(bare.status)} ${bareText.slice(0, 80)}`);
    break;
  } catch (cause) {
    if (!up && Date.now() - started > 19_000) throw cause;
    await new Promise((r) => setTimeout(r, 250));
  }
}

server.kill();
console.log("HTTP transport ok");
