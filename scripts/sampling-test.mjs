/**
 * Proves both assessment paths against the real server over stdio.
 *
 * A sampling-capable client (declares the `sampling` capability and answers createMessage) must get
 * `mode: "sampled"` and a stored verdict; a client without it must get the evidence package and the
 * `save_assessment` follow-up. Hermes is not installed on this host, so the sampling path is proven
 * here with a mock answer rather than live.
 *
 * Usage: node scripts/sampling-test.mjs
 */
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { StdioClientTransport } from "@modelcontextprotocol/sdk/client/stdio.js";
import { CreateMessageRequestSchema } from "@modelcontextprotocol/sdk/types.js";

const data = (res) => res.structuredContent?.result ?? null;

async function run({ sampling }) {
  const transport = new StdioClientTransport({
    command: process.execPath,
    args: ["dist/index.js", "--no-web"],
    cwd: process.cwd(),
    env: { ...process.env, WSMD_DATA_DIR: process.env.WSMD_DATA_DIR },
    stderr: "pipe",
  });
  transport.stderr?.on("data", (chunk) => process.stderr.write(String(chunk)));

  const client = new Client(
    { name: `sampling-test-${sampling ? "on" : "off"}`, version: "0.0.0" },
    { capabilities: sampling ? { sampling: {} } : {}, requestTimeout: 300_000 },
  );

  let promptsSeen = 0;
  if (sampling) {
    client.setRequestHandler(CreateMessageRequestSchema, (req) => {
      promptsSeen += 1;
      const text = req.messages?.[0]?.content?.text ?? "";
      // The mock plays the client's model and answers with the schema the prompt asked for.
      return {
        model: "mock-client-model",
        role: "assistant",
        content: {
          type: "text",
          text:
            "Here is my assessment:\n```json\n" +
            JSON.stringify({
              exe_swap_only: true,
              new_setup_needed: false,
              breaking_change_expected: false,
              affected_part: null,
              reason: "Sampled verdict from the mock client model.",
              confidence: "high",
            }) +
            "\n```",
        },
      };
    });
  }

  await client.connect(transport);

  const scan = await client.callTool({ name: "scan_inventory", arguments: { sources: ["registry", "winget"] } });
  if (scan.isError) throw new Error(`scan_inventory failed: ${scan.content[0].text}`);

  const check = await client.callTool({ name: "check_cves", arguments: { with_epss: false } });
  if (check.isError) throw new Error(`check_cves failed: ${check.content[0].text}`);

  // Any status works here: what this test proves is the assessment channel, not the status machine.
  const todos = await client.callTool({ name: "list_todos", arguments: { status: "all", limit: 1 } });
  const target = data(todos)?.todos?.[0];
  if (!target) throw new Error("no todo was produced; cannot exercise the assessment path");

  const assess = await client.callTool({ name: "assess_todo", arguments: { todo_id: target.id } });
  const ad = data(assess);

  await client.close();

  return { sampling, todo: target.id, mode: ad?.mode, assessment: ad?.assessment ?? null, promptsSeen };
}

const on = await run({ sampling: true });
const off = await run({ sampling: false });

const report = (r) =>
  `  sampling=${String(r.sampling).padEnd(5)} mode=${String(r.mode).padEnd(16)} createMessage calls=${String(r.promptsSeen)}  axes(a,b,c)=${
    r.assessment ? [r.assessment.exe_swap_only, r.assessment.new_setup_needed, r.assessment.breaking_change_expected].join("/") : "n/a"
  }  assessed_by=${r.assessment?.assessed_by ?? "n/a"}`;

console.log("[sampling paths]");
console.log(report(on));
console.log(report(off));

let failed = false;
if (on.mode !== "sampled" || on.assessment?.assessed_by !== "client_sampling" || on.promptsSeen !== 1) {
  console.error("FAIL: the sampling-capable client did not get a sampled verdict stored by the server");
  failed = true;
}
if (off.mode !== "evidence_package" || off.promptsSeen !== 0) {
  console.error("FAIL: the non-sampling client did not get the evidence package fallback");
  failed = true;
}
console.log(failed ? "RESULT: FAIL" : "RESULT: PASS — both assessment paths behave as specified");
process.exitCode = failed ? 1 : 0;
