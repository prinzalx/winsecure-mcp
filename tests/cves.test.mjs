import assert from "node:assert/strict";
import { test } from "node:test";

import { normName } from "../dist/utils/matching.js";
import { kevForProduct } from "../dist/modules/cves/feeds.js";
import { candidates, versionAffected, matchProgram, eraImplausible } from "../dist/modules/cves/engine.js";
import { enrichKevHits } from "../dist/modules/cves/index.js";

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

test("eraImplausible drops the obviously impossible name matches", () => {
  // The live beta's four false positives, from the report of 10/2026.
  assert.equal(eraImplausible("155.0.4283.45", "2016-10-11T00:00:00Z"), true, "EdgeHTML bug vs. Edge 155");
  assert.equal(eraImplausible("2.2639.100.0", "2019-01-01T00:00:00Z"), true, "2019 WhatsApp bug vs. a current build");
  // A 2025 CVE against 7-Zip 26.02 stays plausibly kept; its real exclusion comes with the range.
  assert.equal(eraImplausible("26.02", "2025-01-01T00:00:00Z"), false);
  // No publication date means no era verdict, which keeps the (unconfirmed) hit.
  assert.equal(eraImplausible("155.0.4283.45", null), false);
  assert.equal(eraImplausible(null, "2016-10-11T00:00:00Z"), false);
});

test("a KEV name match the era heuristic rejects is dropped and counted", () => {
  const entry = { id: "x", name: "Microsoft Edge", version: "155.0.4283.45", publisher: null, sources: [], package_ids: [], paths: [], match_hint: null, first_seen: "", last_seen: "" };
  const index = { byProduct: new Map(), byCve: new Map(), totalCves: 1, products: 0, fetched_at: null, from: "cache" };
  const kev = kevIndex([kevRow("CVE-2016-7200", "Microsoft Edge")]);
  const { hits, dropped } = matchProgram(entry, index, kev);
  assert.deepEqual(hits, [], "a 2016 CVE must not headline Edge 155");
  assert.equal(dropped, 1);
});

test("a range that excludes the installed version is a counted not_affected verdict", () => {
  const entry = { id: "x", name: "Git", version: "2.55.0.3", publisher: null, sources: [], package_ids: [], paths: [], match_hint: null, first_seen: "", last_seen: "" };
  const record = { cve_id: "CVE-2025-48384", product: "git", vendor: null, summary: null, published: "2025-10-01T00:00:00Z", cvss: 8, range_from: null, range_below: "2.50.1", fixed_version: "2.50.1" };
  const index = { byProduct: new Map([[normName("git"), [record]]]), byCve: new Map([["CVE-2025-48384", record]]), totalCves: 1, products: 1, fetched_at: null, from: "cache" };
  const kev = kevIndex([kevRow("CVE-2025-48384", "Git")]);
  const { hits, dropped } = matchProgram(entry, index, kev);
  assert.deepEqual(hits, []);
  assert.equal(dropped, 1, "installed 2.55.0.3 is above the affected range, so the pair is impossible");
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

test("enrichKevHits applies one NVD answer to every hit object of that CVE id", async () => {
  // The live beta showed the same CVE enriched on one Edge to-do (8.8) and null on the other: the
  // old loop enriched only the first hit object per id. Both objects must carry the score now.
  const kevHit = (over = {}) => ({
    cve_id: "CVE-2016-7201", cvss: null, severity: "none", kev: true, kev_due_date: null, epss: null,
    fixed_version: null, matched_by: "kev_product", match_confidence: "low", summary: null, published: null, ...over,
  });
  const a = kevHit();
  const b = kevHit();
  let calls = 0;
  const ctx = {
    config: { settings: { httpTimeoutMs: 1000 } },
    http: {
      get: async () => {
        calls += 1;
        return {
          body: JSON.stringify({ vulnerabilities: [{ cve: {
            published: "2016-11-01T00:00:00Z",
            descriptions: [{ lang: "en", value: "Edge memory corruption" }],
            metrics: { cvssMetricV31: [{ cvssData: { baseScore: 8.8 } }] },
          } }] }),
          from: "cache",
          fetched_at: null,
        };
      },
    },
  };
  const enriched = await enrichKevHits(ctx, [a, b]);
  assert.equal(enriched, 1, "one CVE, one lookup, counted once");
  assert.equal(calls, 1, "each CVE id is fetched at most once per run");
  assert.equal(a.cvss, 8.8);
  assert.equal(b.cvss, 8.8, "the duplicate object of the same CVE id must not stay null");
  assert.equal(b.severity, "high");
  assert.equal(b.cvss_source, "nvd");
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
