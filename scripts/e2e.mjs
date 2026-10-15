/**
 * End-to-end driver over real stdio MCP: starts dist/index.js as a child process, performs the
 * handshake, and calls the whole tool chain. Used for the acceptance run and for the offline test.
 *
 * Usage: node scripts/e2e.mjs [--assess] [--offline]
 */
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { StdioClientTransport } from "@modelcontextprotocol/sdk/client/stdio.js";

const argv = process.argv.slice(2);
const doAssess = argv.includes("--assess");

const env = { ...process.env };
if (argv.includes("--offline")) env.WSMD_OFFLINE = "1";

const transport = new StdioClientTransport({
  command: process.execPath,
  args: ["dist/index.js", "--no-web"],
  cwd: process.cwd(),
  env,
  stderr: "pipe",
});

const client = new Client({ name: "e2e-driver", version: "0.0.0" }, { requestTimeout: 300_000 });
// The portable walk legitimately runs up to its 60 s budget, so the SDK default of 60 s is too tight.
await client.connect(transport, { timeout: 300_000 });

const line = (label, value) => console.log(`${label}: ${typeof value === "string" ? value : JSON.stringify(value)}`);
const data = (res) => res.structuredContent?.result ?? null;
const firstText = (res) => res.content?.[0]?.text ?? "";

const tools = await client.listTools();
line("tools", tools.tools.map((t) => t.name).join(", "));

const scan = await client.callTool({ name: "scan_inventory", arguments: {} }, undefined, { timeout: 300_000 });
console.log("[scan_inventory]", firstText(scan));
line("  counters", data(scan)?.counters);
line("  deduplicated", data(scan)?.deduplicated);
line("  source_errors", data(scan)?.source_errors ?? "none");
line("  portable report", data(scan)?.report?.portable);

const check = await client.callTool({ name: "check_cves", arguments: {} }, undefined, { timeout: 300_000 });
console.log("[check_cves]", firstText(check));
const cd = data(check) ?? {};
line("  cve_status", cd.cve_status);
line("  programs_with_hits", cd.programs_with_hits);
line("  cve_hits", cd.cve_hits);
line("  kev_hits", cd.kev_hits);
line("  kev", cd.kev);
line("  cvelist", cd.cvelist);
line("  source_errors", cd.source_errors);

const todos = await client.callTool({ name: "list_todos", arguments: { status: "open", limit: 5 } });
console.log("[list_todos]\n" + firstText(todos));

if (doAssess) {
  const shown = data(todos)?.todos ?? [];
  const target = shown[0];
  if (target) {
    const assess = await client.callTool({ name: "assess_todo", arguments: { todo_id: target.id } });
    console.log("[assess_todo]", firstText(assess).slice(0, 300));
    const ad = data(assess) ?? {};
    line("  mode", ad.mode);
    line("  evidence axes", ad.evidence?.axes);
    line("  evidence program", `${ad.evidence?.program ?? ""} ${ad.evidence?.version ?? ""}`.trim());
    line("  evidence kev_cves", ad.evidence?.kev_cves);

    const saved = await client.callTool({
      name: "save_assessment",
      arguments: {
        todo_id: target.id,
        exe_swap_only: false,
        new_setup_needed: true,
        breaking_change_expected: false,
        reason: "Vendor ships a setup package for this program, so the update is a re-install rather than a file swap.",
        confidence: "medium",
      },
    });
    console.log("[save_assessment]", firstText(saved));
    const after = await client.callTool({ name: "list_todos", arguments: { status: "assessed", limit: 5 } });
    console.log("[list_todos assessed]\n" + firstText(after));
  } else {
    console.log("[assess_todo] no open todo to assess");
  }
}

const firstProgram = data(todos)?.todos?.[0]?.program ?? "chrome";
const gp = data(await client.callTool({ name: "get_program", arguments: { program: firstProgram } }));
const m = gp?.matches?.[0];
line("get_program", m ? `${m.name} ${m.version ?? ""} sources=${JSON.stringify(m.sources.map((s) => s.source))} cves=${m.cves?.length ?? 0}` : "no match");

const detail = await client.callTool({ name: "cve_detail", arguments: { cve_id: "CVE-2024-21412" } });
console.log("[cve_detail]", firstText(detail).slice(0, 300));

await client.close();
