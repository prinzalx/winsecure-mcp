import assert from "node:assert/strict";
import { test } from "node:test";

import { computeState, createActivity } from "../dist/dashboard.js";

function todo(id, over = {}) {
  return {
    id,
    inventory_id: `inv-${id}`,
    program: `Program ${id}`,
    version: "1.0",
    publisher: null,
    unconfirmed_cves: [],
    kev_confirmed: false,
    cves: [{ cve_id: `CVE-2024-000${id}`, cvss: 7, severity: "high", kev: false, kev_due_date: null, epss: null, fixed_version: null, matched_by: "cvelist_product", match_confidence: "high", summary: null, published: null }],
    max_severity: "high",
    max_cvss: 7,
    any_kev: false,
    max_epss: null,
    fix_version: null,
    match_confidence: "high",
    cve_status: "checked",
    status: "open",
    assessment: null,
    created_at: "2026-01-01T00:00:00.000Z",
    updated_at: "2026-01-01T00:00:00.000Z",
    ...over,
  };
}

function state(store) {
  return computeState({
    version: "0.0.0-test",
    store: { schema: 1, updated_at: "2026-01-01T00:00:00.000Z", ...store },
    storeExists: true,
    dataDir: "/tmp/x",
    storePath: "/tmp/x/winsecure.json",
    tools: [],
    activity: [],
    clientSampling: null,
  });
}

test("computeState counts inventory per source, package ids and paths", () => {
  const s = state({
    inventory: [
      {
        id: "a", name: "A", version: "1", publisher: null,
        sources: [
          { source: "registry", name: "A", version: "1", publisher: null, package_id: "Acme.A", path: null, registry_key: null, install_source: null },
          { source: "winget", name: "A", version: "1", publisher: null, package_id: "Acme.A", path: null, registry_key: null, install_source: null },
        ],
        package_ids: ["Acme.A"], paths: [], match_hint: "Acme.A", first_seen: "", last_seen: "",
      },
      {
        id: "b", name: "B", version: null, publisher: null,
        sources: [{ source: "portable", name: "B", version: null, publisher: null, package_id: null, path: "D:\\b\\b.exe", registry_key: null, install_source: null }],
        package_ids: [], paths: ["D:\\b\\b.exe"], match_hint: "b", first_seen: "", last_seen: "",
      },
    ],
    todos: [],
  });
  assert.equal(s.inventory.programs, 2);
  assert.deepEqual(s.inventory.per_source, { registry: 1, winget: 1, portable: 1 });
  assert.equal(s.inventory.with_package_id, 1);
  assert.equal(s.inventory.with_path, 1);
});

test("computeState aggregates todo statuses, KEV and severity bands", () => {
  const s = state({
    inventory: [],
    todos: [
      todo("1"),
      todo("2", { status: "assessed", any_kev: true, assessment: { assessed_by: "client_saved" } }),
      todo("3", { status: "dismissed" }),
      todo("4", { max_severity: "critical", max_epss: 0.9, any_kev: true }),
    ],
  });
  assert.equal(s.todos.total, 4);
  assert.equal(s.todos.open, 2);
  assert.equal(s.todos.assessed, 1);
  assert.equal(s.todos.dismissed, 1);
  // Dismissed entries are excluded from the KEV/severity/EPSS statistics.
  assert.equal(s.todos.kev, 2);
  assert.equal(s.todos.by_severity.critical, 1);
  assert.equal(s.todos.by_severity.high, 2);
  assert.equal(s.todos.with_epss, 1);
  assert.equal(s.todos.assessed_share, 33);
});

test("computeState orders the top risks confirmed-KEV first, then severity", () => {
  const s = state({
    inventory: [],
    todos: [
      todo("plain"),
      todo("kev", { any_kev: true, kev_confirmed: true, max_severity: "medium", cves: [{ cve_id: "CVE-2024-000kev", cvss: 6, severity: "medium", kev: true, kev_due_date: null, epss: null, fixed_version: null, matched_by: "kev_product", match_confidence: "medium", summary: null, published: null }] }),
      // A KEV marker with no verified hit behind it must not outrank a confirmed finding.
      todo("kev-unverified", { any_kev: true, max_severity: "none", max_cvss: null, unconfirmed_cves: ["CVE-2024-000u"], cves: [{ cve_id: "CVE-2024-000u", cvss: 9.8, severity: "critical", kev: true, kev_due_date: null, epss: null, fixed_version: null, matched_by: "kev_product", match_confidence: "low", summary: null, published: null, unconfirmed: true }] }),
      todo("crit", { max_severity: "critical" }),
    ],
  });
  assert.deepEqual(s.todos.top.map((t) => t.id), ["kev", "crit", "plain", "kev-unverified"]);
  assert.equal(s.todos.with_unconfirmed, 1);
});

test("an empty store yields zeroed statistics and no top rows — empty is not an error", () => {
  const s = state({ inventory: [], todos: [] });
  assert.equal(s.inventory.programs, 0);
  assert.equal(s.todos.total, 0);
  assert.equal(s.todos.assessed_share, null);
  assert.deepEqual(s.todos.top, []);
});

test("createActivity keeps the newest entries first and caps the ring", () => {
  const activity = createActivity(3);
  for (let i = 1; i <= 5; i += 1) {
    activity.add({ at: `t${String(i)}`, tool: `tool${String(i)}`, ok: true, duration_ms: i, origin: "stdio", summary: "" });
  }
  const recent = activity.recent();
  assert.deepEqual(recent.map((a) => a.tool), ["tool5", "tool4", "tool3"]);
  assert.deepEqual(activity.recent(1).map((a) => a.tool), ["tool5"]);
});
