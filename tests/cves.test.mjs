import assert from "node:assert/strict";
import { test } from "node:test";

import { normName } from "../dist/utils/matching.js";
import { kevForProduct } from "../dist/modules/cves/feeds.js";
import { candidates, versionAffected, matchProgram } from "../dist/modules/cves/engine.js";

function kevIndex(rows) {
  const byProduct = new Map();
  const byCve = new Map();
  for (const r of rows) {
    byCve.set(r.cve_id, r);
    const key = normName(r.product);
    const list = byProduct.get(key) ?? [];
    list.push(r);
    byProduct.set(key, list);
  }
  return { byProduct, byCve, total: byCve.size, fetched_at: null, from: "cache" };
}

const kevRow = (cve_id, product) => ({ cve_id, product, vendor: null, due_date: "2026-10-01", name: cve_id });

test("kevForProduct uses the alias table across the display-name gap", () => {
  const kev = kevIndex([kevRow("CVE-2026-1000", "Chrome"), kevRow("CVE-2026-2000", "WinRAR")]);
  assert.deepEqual(kevForProduct(kev, "Google Chrome").map((e) => e.cve_id), ["CVE-2026-1000"]);
  assert.deepEqual(kevForProduct(kev, "WinRAR").map((e) => e.cve_id), ["CVE-2026-2000"]);
  assert.deepEqual(kevForProduct(kev, "Unrelated App"), []);
});

test("candidates ranks the display name first and dedupes", () => {
  const entry = {
    id: "x", name: "Google Chrome", version: "120.0", publisher: null, sources: [],
    package_ids: ["Google.Chrome"], paths: [], match_hint: "Google.Chrome", first_seen: "", last_seen: "",
  };
  const list = candidates(entry);
  assert.equal(list[0].name, "Google Chrome");
  assert.equal(list[0].confidence, "high");
  const keys = list.map((c) => c.name.toLowerCase());
  assert.equal(new Set(keys).size, keys.length);
});

test("versionAffected respects a numeric below-bound", () => {
  const rec = { cve_id: "CVE", product: "p", vendor: null, summary: null, published: null, cvss: 5, range_from: "1.0.0", range_below: "1.4.0", fixed_version: "1.4.0" };
  assert.deepEqual(versionAffected("1.2.0", rec), { affected: true, exact: true });
  assert.deepEqual(versionAffected("1.4.0", rec), { affected: false, exact: true });
  assert.deepEqual(versionAffected("2.0.0", rec), { affected: false, exact: true });
});

test("versionAffected degrades to an unsure match instead of a false negative", () => {
  const rec = { cve_id: "CVE", product: "p", vendor: null, summary: null, published: null, cvss: 5, range_from: null, range_below: "1.4.0a", fixed_version: null };
  const verdict = versionAffected("9.9.9", rec);
  assert.equal(verdict.affected, true);
  assert.equal(verdict.exact, false);
});

test("matchProgram reports checked=false when no CVE data is loaded", () => {
  const entry = { id: "x", name: "Tool", version: "1.0", publisher: null, sources: [], package_ids: [], paths: [], match_hint: "tool", first_seen: "", last_seen: "" };
  const emptyIndex = { byProduct: new Map(), byCve: new Map(), totalCves: 0, products: 0, fetched_at: null, from: "none" };
  const res = matchProgram(entry, emptyIndex, kevIndex([]));
  assert.equal(res.checked, false);
  assert.deepEqual(res.hits, []);
});

test("matchProgram marks the product-index hit and lets KEV flag exploitation", () => {
  const entry = { id: "x", name: "Example Toolbar", version: "1.2.0", publisher: null, sources: [], package_ids: [], paths: [], match_hint: "example toolbar", first_seen: "", last_seen: "" };
  const index = {
    byProduct: new Map([
        ["example toolbar", [
        { cve_id: "CVE-2026-1000", product: "Example Toolbar", vendor: null, summary: "s", published: "2026-01-01T00:00:00Z", cvss: 9.1, range_from: "1.0.0", range_below: "1.5.0", fixed_version: "1.5.0" },
        { cve_id: "CVE-2026-2000", product: "Example Toolbar", vendor: null, summary: "s", published: null, cvss: 4, range_from: "1.0.0", range_below: "1.1.0", fixed_version: "1.1.0" },
      ]],
    ]),
    byCve: new Map(),
    totalCves: 2, products: 1, fetched_at: null, from: "cache",
  };
  const kev = kevIndex([kevRow("CVE-2026-1000", "Example Toolbar"), kevRow("CVE-2026-3000", "Example Toolbar")]);
  const { hits, checked } = matchProgram(entry, index, kev);
  assert.equal(checked, true);

  const exploited = hits.find((h) => h.cve_id === "CVE-2026-1000");
  assert.equal(exploited.kev, true);
  assert.equal(exploited.kev_due_date, "2026-10-01");
  assert.equal(exploited.severity, "critical");
  assert.equal(exploited.fixed_version, "1.5.0");

  // The version range excludes this one, so it must not appear as a hit.
  assert.equal(hits.find((h) => h.cve_id === "CVE-2026-2000"), undefined);

  // A KEV entry with no record behind it is kept, but unconfirmed: no version verdict is possible.
  const kevOnly = hits.find((h) => h.cve_id === "CVE-2026-3000");
  assert.equal(kevOnly.matched_by, "kev_product");
  assert.equal(kevOnly.cvss, null);
  assert.equal(kevOnly.unconfirmed, true);
  assert.equal(kevOnly.match_confidence, "low");
});

test("a KEV name match inside the record's version range is a confirmed hit", () => {
  const entry = { id: "x", name: "Google Chrome", version: "120.0.6099.109", publisher: null, sources: [], package_ids: [], paths: [], match_hint: null, first_seen: "", last_seen: "" };
  const record = { cve_id: "CVE-2020-16017", product: "chrome", vendor: "google", summary: "sandbox escape", published: null, cvss: 9.6, range_from: null, range_below: "86.0.4240.198", fixed_version: "86.0.4240.198" };
  const index = { byProduct: new Map(), byCve: new Map([["CVE-2020-16017", record]]), totalCves: 1, products: 0, fetched_at: null, from: "cache" };
  const kev = kevIndex([kevRow("CVE-2020-16017", "Chrome")]);
  const { hits } = matchProgram(entry, index, kev);
  assert.equal(hits.length, 0, "Chrome 120 is above the affected range, so the hit must be dropped");
});

test("a KEV name match below the range stays a hit and is not marked unconfirmed", () => {
  const entry = { id: "x", name: "Google Chrome", version: "85.0.4183.121", publisher: null, sources: [], package_ids: [], paths: [], match_hint: null, first_seen: "", last_seen: "" };
  const record = { cve_id: "CVE-2020-16017", product: "chrome", vendor: "google", summary: null, published: null, cvss: 9.6, range_from: null, range_below: "86.0.4240.198", fixed_version: "86.0.4240.198" };
  const index = { byProduct: new Map(), byCve: new Map([["CVE-2020-16017", record]]), totalCves: 1, products: 0, fetched_at: null, from: "cache" };
  const kev = kevIndex([kevRow("CVE-2020-16017", "Chrome")]);
  const { hits } = matchProgram(entry, index, kev);
  assert.equal(hits.length, 1);
  assert.equal(hits[0].kev, true);
  assert.equal(hits[0].unconfirmed, undefined);
  assert.equal(hits[0].cvss, 9.6);
  assert.equal(hits[0].cvss_source, "cvelist");
});

test("an unverifiable KEV range is kept as a low-confidence unconfirmed hit", () => {
  const entry = { id: "x", name: "Obscure App", version: "9.9", publisher: null, sources: [], package_ids: [], paths: [], match_hint: null, first_seen: "", last_seen: "" };
  const index = { byProduct: new Map(), byCve: new Map(), totalCves: 1, products: 0, fetched_at: null, from: "cache" };
  const kev = kevIndex([kevRow("CVE-2026-4242", "Obscure App")]);
  const { hits } = matchProgram(entry, index, kev);
  assert.equal(hits.length, 1);
  assert.equal(hits[0].unconfirmed, true);
  assert.equal(hits[0].match_confidence, "low");
});

test("a KEV-only hit is enriched from the local index by CVE id", () => {
  const entry = { id: "x", name: "Example Toolbar", version: "1.2.0", publisher: null, sources: [], package_ids: [], paths: [], match_hint: "example toolbar", first_seen: "", last_seen: "" };
  const record = { cve_id: "CVE-2026-3000", product: "Example Toolbar", vendor: null, summary: "remote code execution", published: "2026-02-02T00:00:00Z", cvss: 7.5, range_from: null, range_below: null, fixed_version: "1.3.0" };
  const index = {
    byProduct: new Map(),
    byCve: new Map([["CVE-2026-3000", record]]),
    totalCves: 1, products: 0, fetched_at: null, from: "cache",
  };
  const kev = kevIndex([kevRow("CVE-2026-3000", "Example Toolbar")]);
  const { hits } = matchProgram(entry, index, kev);
  const hit = hits.find((h) => h.cve_id === "CVE-2026-3000");
  assert.equal(hit.matched_by, "kev_product");
  assert.equal(hit.cvss, 7.5);
  assert.equal(hit.severity, "high");
  assert.equal(hit.fixed_version, "1.3.0");
  assert.equal(hit.summary, "remote code execution");
  assert.equal(hit.published, "2026-02-02T00:00:00Z");
});
