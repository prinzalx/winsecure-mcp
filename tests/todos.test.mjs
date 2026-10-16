import assert from "node:assert/strict";
import { test } from "node:test";

import { buildTodo, mergeTodo, normalizeAssessment, severityRank, buildEvidence, todoId, compareTodoRank, groupMatchesIntoTodos, ratingConfidence } from "../dist/modules/todos/todo.js";
import { parseJsonObject, todoTools } from "../dist/modules/todos/index.js";

function hit(cveId, over = {}) {
  return {
    cve_id: cveId,
    cvss: null,
    severity: "none",
    kev: false,
    kev_due_date: null,
    epss: null,
    fixed_version: null,
    matched_by: "cvelist_product",
    match_confidence: "high",
    summary: null,
    published: null,
    ...over,
  };
}

const entry = {
  id: "abc123",
  name: "Example Tool",
  version: "1.2.3",
  publisher: "Acme",
  sources: [
    { source: "registry", name: "Example Tool", version: "1.2.3", publisher: "Acme", package_id: null, path: null, registry_key: "HKLM", install_source: "C:\\Installers" },
  ],
  package_ids: [],
  paths: [],
  match_hint: "example tool",
  first_seen: "",
  last_seen: "",
};

test("buildTodo aggregates severity, KEV, EPSS and the newest fix version", () => {
  const todo = buildTodo(entry, [
    hit("CVE-2024-0001", { cvss: 5.0, epss: 0.1 }),
    hit("CVE-2024-0002", { cvss: 9.8, epss: 0.4, fixed_version: "1.5.0" }),
    hit("CVE-2024-0003", { cvss: 7.5, fixed_version: "1.4.0" }),
  ], "high", "checked");

  assert.equal(todo.max_severity, "critical");
  assert.equal(todo.max_cvss, 9.8);
  assert.equal(todo.max_epss, 0.4);
  assert.equal(todo.fix_version, "1.5.0");
  assert.equal(todo.any_kev, false);
  assert.equal(todo.status, "open");
  assert.equal(todo.cve_status, "checked");
});

test("buildTodo promotes a KEV hit to at least high", () => {
  const todo = buildTodo(entry, [hit("CVE-2024-0009", { cvss: 3.1, kev: true })], "medium", "checked");
  assert.equal(todo.max_severity, "high");
  assert.equal(todo.any_kev, true);
});

test("buildTodo keeps an unconfirmed KEV match out of the severity rating", () => {
  const todo = buildTodo(entry, [hit("CVE-2024-0001", { cvss: 5, kev: true, unconfirmed: true })], "low", "checked");
  assert.deepEqual(todo.unconfirmed_cves, ["CVE-2024-0001"]);
  // The CVSS column still reports the score (it is a fact about the CVE), but neither the band nor
  // the KEV promotion to high applies, so the entry carries no severity claim of its own.
  assert.equal(todo.max_severity, "none");
  assert.equal(todo.max_cvss, 5);
  assert.equal(todo.any_kev, true);

  // A confirmed hit of the same severity is rated, so the separation only concerns the unconfirmed one.
  const mixed = buildTodo(entry, [
    hit("CVE-2024-0001", { cvss: 9, kev: true, unconfirmed: true }),
    hit("CVE-2024-0002", { cvss: 3 }),
  ], "low", "checked");
  assert.equal(mixed.max_severity, "low");
  assert.equal(mixed.max_cvss, 9);
});

test("groupMatchesIntoTodos merges versions of one product family into one todo", () => {
  const base = { publisher: null, sources: [], package_ids: [], paths: [], match_hint: null, first_seen: "", last_seen: "" };
  const edge152 = { id: "inv-152", name: "Microsoft Edge", version: "152.0.4191.53", ...base };
  const edge155 = { id: "inv-155", name: "Microsoft Edge", version: "155.0.4283.45", ...base };
  const kevHit = { cve_id: "CVE-2016-7200", cvss: 8.8, severity: "high", kev: true, kev_due_date: null, epss: null, fixed_version: null, matched_by: "kev_product", match_confidence: "low", summary: null, published: null, unconfirmed: true };
  const todos = groupMatchesIntoTodos([
    { family: "microsoft edge", entry: edge152, hits: [kevHit], cveStatus: "checked" },
    { family: "microsoft edge", entry: edge155, hits: [{ ...kevHit }], cveStatus: "checked" },
  ]);
  assert.equal(todos.length, 1, "the two Edge versions must share one to-do");
  assert.equal(todos[0].version, "155.0.4283.45", "the newest version represents the group");
  assert.deepEqual(todos[0].versions.map((v) => v.version), ["155.0.4283.45", "152.0.4191.53"], "members newest first");
  assert.equal(todos[0].cves.length, 1, "one row per CVE, not one per version");
});

test("an entry without a family stays its own todo and carries no versions list", () => {
  const base = { publisher: null, sources: [], package_ids: [], paths: [], match_hint: null, first_seen: "", last_seen: "" };
  const only = { id: "inv-1", name: "Obscure", version: null, ...base };
  const hit = { cve_id: "CVE-2026-1", cvss: null, severity: "none", kev: true, kev_due_date: null, epss: null, fixed_version: null, matched_by: "kev_product", match_confidence: "low", summary: null, published: null, unconfirmed: true };
  const todos = groupMatchesIntoTodos([{ family: "", entry: only, hits: [hit], cveStatus: "checked" }]);
  assert.equal(todos.length, 1);
  assert.equal(todos[0].versions, undefined);
  assert.equal(ratingConfidence([hit]), "low");
});

test("compareTodoRank never lets an unconfirmed KEV hit outrank a confirmed finding", () => {
  const base = { id: "x", name: "P", version: "1.0", publisher: null, sources: [], package_ids: [], paths: [], match_hint: null, first_seen: "", last_seen: "" };
  const unconfirmed = buildTodo(base, [hit("CVE-U", { cvss: 9.8, kev: true, unconfirmed: true })], "low", "checked");
  const confirmedKev = buildTodo(base, [hit("CVE-K", { cvss: 6, kev: true })], "high", "checked");
  const confirmedPlain = buildTodo(base, [hit("CVE-C", { cvss: 8.9 })], "high", "checked");
  const sorted = [unconfirmed, confirmedPlain, confirmedKev].sort(compareTodoRank);
  assert.deepEqual(sorted.map((t) => t.cves[0].cve_id), ["CVE-K", "CVE-C", "CVE-U"]);
});

test("todoId is stable for the same facts and changes with a new CVE set", () => {
  const a = todoId("abc", ["CVE-2", "CVE-1"]);
  assert.equal(a, todoId("abc", ["CVE-1", "CVE-2"]));
  assert.notEqual(a, todoId("abc", ["CVE-1"]));
});

test("mergeTodo keeps status, assessment and created_at, refreshes the CVE facts", () => {
  const first = buildTodo(entry, [hit("CVE-2024-0001", { cvss: 5 })], "high", "checked");
  const assessed = { ...first, status: "assessed", assessment: { reason: "known", confidence: "high" } };

  const fresh = buildTodo(entry, [
    hit("CVE-2024-0001", { cvss: 6.5 }),
    hit("CVE-2024-0002", { cvss: 8 }),
  ], "high", "checked");
  const same = { ...fresh, id: first.id };

  const merged = mergeTodo([assessed], same);
  assert.equal(merged.status, "assessed");
  assert.equal(merged.assessment, assessed.assessment);
  assert.equal(merged.created_at, first.created_at);
  assert.equal(merged.cves.length, 2);
  assert.equal(merged.cves.find((c) => c.cve_id === "CVE-2024-0001").cvss, 6.5);
});

test("severityRank orders the bands so KEV-heavy work sorts first", () => {
  assert.ok(severityRank("critical") > severityRank("high"));
  assert.ok(severityRank("high") > severityRank("medium"));
  assert.ok(severityRank("medium") > severityRank("low"));
});

test("list_todos puts KEV first, then severity, then CVSS", () => {
  const rows = [
    buildTodo(entry, [hit("CVE-1", { cvss: 5 })], "high", "checked"),
    buildTodo(entry, [hit("CVE-2", { cvss: 9.8, kev: true })], "high", "checked"),
    buildTodo(entry, [hit("CVE-3", { cvss: 7 })], "high", "checked"),
  ];
  const sorted = [...rows].sort(compareTodoRank);
  assert.deepEqual(sorted.map((t) => t.cves[0].cve_id), ["CVE-2", "CVE-3", "CVE-1"]);
});

test("normalizeAssessment coerces booleans and validates confidence", () => {
  const a = normalizeAssessment(
    { exe_swap_only: 1, new_setup_needed: 0, breaking_change_expected: true, affected_part: "", reason: "ok", confidence: "bogus" },
    "client_saved",
  );
  assert.equal(a.exe_swap_only, true);
  assert.equal(a.new_setup_needed, false);
  assert.equal(a.affected_part, null);
  assert.equal(a.confidence, "medium");
  assert.equal(a.assessed_by, "client_saved");
  assert.match(a.assessed_at, /^\d{4}-\d{2}-\d{2}T.*Z$/);
});

test("buildEvidence exposes exactly the axes a-d and the CVE signals", () => {
  const todo = buildTodo(entry, [hit("CVE-2024-0001", { kev: true })], "medium", "checked");
  const ev = buildEvidence(todo, entry);
  assert.deepEqual(Object.keys(ev.axes), ["a", "b", "c", "d"]);
  assert.deepEqual(ev.kev_cves, ["CVE-2024-0001"]);
  assert.equal(ev.program, "Example Tool");
  assert.ok(ev.install_sources.includes("registry"));
  assert.equal(ev.match_confidence, "medium");
});

test("save_assessment accepts an explicit null affected_part", () => {
  const tool = todoTools.find((t) => t.name === "save_assessment");
  const base = { todo_id: "todo-1", exe_swap_only: false, new_setup_needed: true, breaking_change_expected: false, reason: "vendor setup" };
  // The docs and the skill tell the agent "otherwise null", so null must parse.
  const nullParsed = tool.input.safeParse({ ...base, affected_part: null });
  assert.equal(nullParsed.success, true, JSON.stringify(nullParsed.error?.issues));
  assert.equal(nullParsed.data.affected_part, null);
  assert.equal(tool.input.safeParse({ ...base, affected_part: "WebView2" }).success, true);
  assert.equal(tool.input.safeParse({ ...base, affected_part: 5 }).success, false);
  assert.equal(tool.input.safeParse({ ...base, todo_id: "" }).success, false);
});

test("parseJsonObject survives prose and code fences", () => {
  assert.deepEqual(parseJsonObject('{"a":1}'), { a: 1 });
  assert.deepEqual(parseJsonObject('```json\n{"a":1}\n```'), { a: 1 });
  assert.deepEqual(parseJsonObject('Sure! {"a": 1} hope that helps'), { a: 1 });
  assert.equal(parseJsonObject("no json here"), null);
  assert.equal(parseJsonObject("[1,2]"), null);
});
