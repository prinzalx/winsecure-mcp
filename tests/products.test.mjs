import assert from "node:assert/strict";
import { mkdtempSync, readdirSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { test } from "node:test";

import {
  looksLikeNvdKey,
  lookupProducts,
  mergeRecords,
  osvCveId,
  resolveNvdKey,
  validateNvdKey,
} from "../dist/modules/cves/products.js";
import { productNames } from "../dist/modules/cves/index.js";
import { postCached } from "../dist/utils/net.js";

const VALID_KEY = "0123456789abcdef0123456789abcdef";
/** NVD's current format since 2025: a UUID with dashes, not 32 bare hex characters. */
const UUID_KEY = "BB3F4D66-38C9-F111-8377-129478FCB64D";

/** A {@link ConfigStore} stand-in: only `settings.nvdApiKey` matters to the key resolution. */
function configWith(nvdApiKey, extra = {}) {
  return {
    settings: { nvdApiKey, nvdProductsPerRun: 400, nvdMaxPages: 5, httpTimeoutMs: 15000, ...extra },
    path: "<test>",
    save() {},
  };
}

function tempCacheDir() {
  return mkdtempSync(join(tmpdir(), "wsmd-products-"));
}

/** An {@link Http} stand-in whose every answer is the given failure, i.e. an offline run. */
function offlineHttp(cacheDir) {
  return {
    cacheDir,
    async get() {
      return { body: null, from: "none", fetched_at: null, error: "offline" };
    },
    async getBinary() {
      return { body: null, from: "none", fetched_at: null, error: "offline" };
    },
  };
}

test("resolveNvdKey prefers NVD_API_KEY over the saved key", (t) => {
  const previous = process.env.NVD_API_KEY;
  t.after(() => {
    if (previous === undefined) delete process.env.NVD_API_KEY;
    else process.env.NVD_API_KEY = previous;
  });

  process.env.NVD_API_KEY = VALID_KEY;
  assert.deepEqual(resolveNvdKey(configWith("ffffffffffffffffffffffffffff1111")), {
    key: VALID_KEY,
    source: "env",
  });

  delete process.env.NVD_API_KEY;
  assert.deepEqual(resolveNvdKey(configWith("ffffffffffffffffffffffffffff1111")), {
    key: "ffffffffffffffffffffffffffff1111",
    source: "config",
  });

  // An empty env var must not shadow a saved key, and no key at all is `source: null`.
  process.env.NVD_API_KEY = "  ";
  assert.equal(resolveNvdKey(configWith("ffffffffffffffffffffffffffff1111")).source, "config");
  delete process.env.NVD_API_KEY;
  assert.deepEqual(resolveNvdKey(configWith(null)), { key: null, source: null });
});

test("looksLikeNvdKey accepts the old 32-hex and the new UUID format", () => {
  assert.equal(looksLikeNvdKey(VALID_KEY), true);
  assert.equal(looksLikeNvdKey(VALID_KEY.toUpperCase()), true);
  assert.equal(looksLikeNvdKey(`  ${VALID_KEY}  `), true);
  assert.equal(looksLikeNvdKey(UUID_KEY), true);
  assert.equal(looksLikeNvdKey(UUID_KEY.toLowerCase()), true);
  // Dashes are optional, so the same UUID without them passes too.
  assert.equal(looksLikeNvdKey(UUID_KEY.replaceAll("-", "")), true);
  assert.equal(looksLikeNvdKey("abc"), false);
  assert.equal(looksLikeNvdKey(`${VALID_KEY}0`), false);
  assert.equal(looksLikeNvdKey("z123456789abcdef0123456789abcde"), false);
  assert.equal(looksLikeNvdKey("BB3F4D66-38C9-F111-8377-129478FCB64"), false);
});

test("validateNvdKey rejects a malformed key without a network call", async () => {
  const check = await validateNvdKey("not-a-key");
  assert.equal(check.valid, false);
  assert.match(String(check.error), /valid NVD key format/);
  assert.equal((await validateNvdKey("")).valid, false);
});

test("osvCveId pulls the CVE out of every OSV advisory namespace", () => {
  assert.equal(osvCveId("GHSA-4v2v-hcxm-r7wc"), null);
  assert.equal(osvCveId("ALPINE-CVE-2024-2961"), "CVE-2024-2961");
  assert.equal(osvCveId("BIT-CVE-2023-52425"), "CVE-2023-52425");
  assert.equal(osvCveId("GHSA-CVE-2025-12345"), "CVE-2025-12345");
});

const record = (cve_id, product = "Git") => ({
  cve_id,
  product,
  vendor: null,
  summary: null,
  published: null,
  cvss: null,
  range_from: null,
  range_below: null,
  fixed_version: null,
});

test("mergeRecords: an incremental answer adds, a full answer also drops", () => {
  const prev = [record("CVE-2024-1000"), record("CVE-2024-1001")];

  const incremental = mergeRecords(prev, [record("CVE-2024-1001", "git"), record("CVE-2025-2000")], false);
  assert.deepEqual(incremental.map((r) => r.cve_id).sort(), ["CVE-2024-1000", "CVE-2024-1001", "CVE-2025-2000"]);
  // The fresh row wins for the id both answers carry.
  assert.equal(incremental.find((r) => r.cve_id === "CVE-2024-1001").product, "git");

  const full = mergeRecords(prev, [record("CVE-2025-2000")], true);
  assert.deepEqual(full.map((r) => r.cve_id), ["CVE-2025-2000"]);

  // An answer that failed carries no records; the cached ones must survive either way.
  assert.equal(mergeRecords(prev, [], true).length, 2);
  assert.equal(mergeRecords(prev, [], false).length, 2);
});

test("productNames dedupes by normalised name and skips installer artifacts", () => {
  const base = { id: "x", version: "1.0", publisher: null, sources: [], package_ids: [], paths: [], first_seen: "", last_seen: "" };
  const inventory = [
    { ...base, id: "a", name: "Git", match_hint: null },
    { ...base, id: "b", name: "git", match_hint: "Git.Git" },
    { ...base, id: "c", name: "Notepad++ Installer", match_hint: null, installer_artifact: true },
  ];
  const names = productNames(inventory);
  const keys = names.map((n) => n.name);
  assert.equal(new Set(keys).size, keys.length, "each name appears once");
  assert.ok(keys.includes("git"));
  assert.ok(!keys.some((k) => k.includes("notepad")), "the installer-artifact entry is not asked about");
  for (const entry of names) assert.ok(entry.wanted instanceof Set && entry.wanted.size > 0);
});

test("lookupProducts runs keyless when no key exists and reports the mode", async (t) => {
  const previous = process.env.NVD_API_KEY;
  if (previous !== undefined) delete process.env.NVD_API_KEY;
  const wasOffline = process.env.WSMD_OFFLINE;
  process.env.WSMD_OFFLINE = "1";
  const cacheDir = tempCacheDir();
  t.after(() => {
    if (previous !== undefined) process.env.NVD_API_KEY = previous;
    if (wasOffline === undefined) delete process.env.WSMD_OFFLINE;
    else process.env.WSMD_OFFLINE = wasOffline;
    rmSync(cacheDir, { recursive: true, force: true });
  });

  const names = [
    { name: "git", wanted: new Set(["git"]), version: "2.49.1" },
    { name: "7-zip", wanted: new Set(["7-zip"]), version: "26.02" },
  ];
  const result = await lookupProducts({
    http: offlineHttp(cacheDir),
    config: configWith(null),
    cacheDir,
    names,
    ttlMs: 24 * 60 * 60 * 1000,
    force: false,
  });

  assert.equal(result.stats.mode, "keyless-osv+cached");
  // Every product carries a version, so all of them fit into the one OSV batch request.
  assert.equal(result.stats.deferred, 0);
  assert.ok(result.stats.errors.length > 0, "an unreachable feed is reported, not swallowed");
});

test("lookupProducts keeps products without a version out of the OSV batch", async (t) => {
  const previousKey = process.env.NVD_API_KEY;
  if (previousKey !== undefined) delete process.env.NVD_API_KEY;
  const previousOffline = process.env.WSMD_OFFLINE;
  process.env.WSMD_OFFLINE = "1";
  const cacheDir = tempCacheDir();
  t.after(() => {
    if (previousKey !== undefined) process.env.NVD_API_KEY = previousKey;
    if (previousOffline === undefined) delete process.env.WSMD_OFFLINE;
    else process.env.WSMD_OFFLINE = previousOffline;
    rmSync(cacheDir, { recursive: true, force: true });
  });

  // OSV fails a batch query that carries neither version nor commit, and one bad query fails the
  // whole request, so a versionless product must not be sent at all.
  const names = [
    { name: "git", wanted: new Set(["git"]), version: "2.49.1" },
    { name: "Mystery Tool", wanted: new Set(["mystery tool"]), version: null },
  ];
  const result = await lookupProducts({
    http: offlineHttp(cacheDir),
    config: configWith(null),
    cacheDir,
    names,
    ttlMs: 24 * 60 * 60 * 1000,
    force: false,
  });
  assert.equal(result.stats.deferred, 1, "the versionless product is reported as deferred");
});

test("lookupProducts aggregates repeated per-product failures into one line", async (t) => {
  const previousKey = process.env.NVD_API_KEY;
  process.env.NVD_API_KEY = VALID_KEY;
  const previousOffline = process.env.WSMD_OFFLINE;
  process.env.WSMD_OFFLINE = "1";
  const cacheDir = tempCacheDir();
  t.after(() => {
    if (previousKey === undefined) delete process.env.NVD_API_KEY;
    else process.env.NVD_API_KEY = previousKey;
    if (previousOffline === undefined) delete process.env.WSMD_OFFLINE;
    else process.env.WSMD_OFFLINE = previousOffline;
    rmSync(cacheDir, { recursive: true, force: true });
  });

  const names = Array.from({ length: 3 }, (_, i) => ({ name: `product-${String(i)}`, wanted: new Set([`product-${String(i)}`]) }));
  const result = await lookupProducts({
    http: offlineHttp(cacheDir),
    config: configWith(null),
    cacheDir,
    names,
    ttlMs: 24 * 60 * 60 * 1000,
    force: false,
  });

  assert.equal(result.stats.mode, "nvd-keyed");
  assert.equal(result.stats.errors.length, 1, "one line per distinct reason, not one per product");
  assert.match(result.stats.errors[0], /3 products/);
});

test("lookupProducts holds products back at the per-run budget and says so", async (t) => {
  const previousKey = process.env.NVD_API_KEY;
  process.env.NVD_API_KEY = VALID_KEY;
  const previousOffline = process.env.WSMD_OFFLINE;
  process.env.WSMD_OFFLINE = "1";
  const cacheDir = tempCacheDir();
  t.after(() => {
    if (previousKey === undefined) delete process.env.NVD_API_KEY;
    else process.env.NVD_API_KEY = previousKey;
    if (previousOffline === undefined) delete process.env.WSMD_OFFLINE;
    else process.env.WSMD_OFFLINE = previousOffline;
    rmSync(cacheDir, { recursive: true, force: true });
  });

  const names = Array.from({ length: 4 }, (_, i) => ({ name: `p${String(i)}`, wanted: new Set([`p${String(i)}`]) }));
  const result = await lookupProducts({
    http: offlineHttp(cacheDir),
    config: configWith(null, { nvdProductsPerRun: 2 }),
    cacheDir,
    names,
    ttlMs: 24 * 60 * 60 * 1000,
    force: false,
  });

  // Since v0.6.5 `deferred` is what remains open in the persistent queue after the run: the two
  // products the count budget never reached PLUS the two that failed offline and were re-appended
  // at the back for a later attempt. Failures are open work, not done work.
  assert.equal(result.stats.deferred, 4, "the queue's open remainder is visible instead of silent");
});

test("a transient keyed failure leaves the product pending, not done", async (t) => {
  const previousKey = process.env.NVD_API_KEY;
  process.env.NVD_API_KEY = VALID_KEY;
  const previousOffline = process.env.WSMD_OFFLINE;
  process.env.WSMD_OFFLINE = "1";
  const cacheDir = tempCacheDir();
  t.after(() => {
    if (previousKey === undefined) delete process.env.NVD_API_KEY;
    else process.env.NVD_API_KEY = previousKey;
    if (previousOffline === undefined) delete process.env.WSMD_OFFLINE;
    else process.env.WSMD_OFFLINE = previousOffline;
    rmSync(cacheDir, { recursive: true, force: true });
  });

  const names = [{ name: "git", wanted: new Set(["git"]) }];
  const first = await lookupProducts({
    http: offlineHttp(cacheDir),
    config: configWith(null),
    cacheDir,
    names,
    ttlMs: 24 * 60 * 60 * 1000,
    force: false,
  });
  assert.equal(first.stats.failed_other, 1, "the offline failure is counted as transient");
  assert.equal(first.stats.pending, 1, "a failed lookup is NOT done: the product stays pending");
  assert.equal(first.stats.not_found, 0, "a failure is not a negative answer");
});

test("a keyless osv entry does not count fresh in keyed mode", async (t) => {
  const previousKey = process.env.NVD_API_KEY;
  const previousOffline = process.env.WSMD_OFFLINE;
  process.env.WSMD_OFFLINE = "1";
  const cacheDir = tempCacheDir();
  t.after(() => {
    if (previousKey === undefined) delete process.env.NVD_API_KEY;
    else process.env.NVD_API_KEY = previousKey;
    if (previousOffline === undefined) delete process.env.WSMD_OFFLINE;
    else process.env.WSMD_OFFLINE = previousOffline;
    rmSync(cacheDir, { recursive: true, force: true });
  });

  const names = [{ name: "git", wanted: new Set(["git"]), version: "2.49.1" }];
  // A keyless run caches every product from the OSV batch (here: an unreachable batch, but the
  // entry semantics are what matter — write one the way keyless would).
  delete process.env.NVD_API_KEY;
  const keyless = await lookupProducts({
    http: offlineHttp(cacheDir),
    config: configWith(null),
    cacheDir,
    names,
    ttlMs: 24 * 60 * 60 * 1000,
    force: false,
  });
  assert.equal(keyless.stats.mode, "keyless-osv+cached");

  const { readFileSync, writeFileSync, mkdirSync } = await import("node:fs");
  const file = `${cacheDir}/products.json`;
  mkdirSync(cacheDir, { recursive: true });
  writeFileSync(
    file,
    JSON.stringify({
      schema: 1,
      products: {
        git: { name: "git", records: [{ cve_id: "CVE-2024-1000", product: "git", vendor: null, summary: null, published: null, cvss: null, range_from: null, range_below: null, fixed_version: null }], last_modified: null, fetched_at: new Date().toISOString(), source: "osv", truncated: false },
      },
    }),
    "utf8",
  );

  process.env.NVD_API_KEY = VALID_KEY;
  const keyed = await lookupProducts({
    http: offlineHttp(cacheDir),
    config: configWith(null),
    cacheDir,
    names,
    ttlMs: 24 * 60 * 60 * 1000,
    force: false,
  });
  // The osv entry must NOT count fresh in keyed mode: the run asks NVD again (offline that shows
  // as a transient failure, which only happens for a product that was actually queried).
  assert.equal(keyed.stats.failed_other, 1, "keyed mode re-queries an osv-sourced entry to enrich it");
  assert.equal(keyed.stats.pending, 1, "a failed re-fetch leaves it pending, never fresh");
  void readFileSync;
});

test("the keyed queue continues where it stopped instead of restarting at the front", async (t) => {
  const previousKey = process.env.NVD_API_KEY;
  process.env.NVD_API_KEY = VALID_KEY;
  const previousOffline = process.env.WSMD_OFFLINE;
  process.env.WSMD_OFFLINE = "1";
  const cacheDir = tempCacheDir();
  t.after(() => {
    if (previousKey === undefined) delete process.env.NVD_API_KEY;
    else process.env.NVD_API_KEY = previousKey;
    if (previousOffline === undefined) delete process.env.WSMD_OFFLINE;
    else process.env.WSMD_OFFLINE = previousOffline;
    rmSync(cacheDir, { recursive: true, force: true });
  });

  // Every answer is a 429, so every product fails transiently and returns to the queue's back.
  const asked = [];
  const http429 = {
    cacheDir,
    async get(url) {
      asked.push(new URL(url).searchParams.get("keywordSearch"));
      return { body: null, from: "none", fetched_at: null, error: "HTTP 429", status: 429 };
    },
    async getBinary() {
      return { body: null, from: "none", fetched_at: null, error: "HTTP 429", status: 429 };
    },
  };
  const names = Array.from({ length: 4 }, (_, i) => ({ name: `p${String(i)}`, wanted: new Set([`p${String(i)}`]) }));

  const first = await lookupProducts({
    http: http429, config: configWith(null, { nvdProductsPerRun: 2 }), cacheDir, names, ttlMs: 24 * 60 * 60 * 1000, force: false,
  });
  assert.deepEqual(asked, ["p0", "p1"], "the count budget takes the queue head");
  assert.equal(first.stats.failed_429, 2);
  assert.equal(first.stats.deferred, 4, "2 never reached + 2 failed and re-queued are all still open");

  asked.length = 0;
  const second = await lookupProducts({
    http: http429, config: configWith(null, { nvdProductsPerRun: 2 }), cacheDir, names, ttlMs: 24 * 60 * 60 * 1000, force: false,
  });
  assert.deepEqual(asked, ["p2", "p3"], "the second run continues at p2/p3, NOT again at p0/p1 (the v0.6.4 field bug)");
  assert.equal(second.stats.failed_429, 2);

  // And the third run wraps around to the re-queued failures — round-robin, nothing starves.
  asked.length = 0;
  await lookupProducts({
    http: http429, config: configWith(null, { nvdProductsPerRun: 2 }), cacheDir, names, ttlMs: 24 * 60 * 60 * 1000, force: false,
  });
  assert.deepEqual(asked, ["p0", "p1"], "failed products wait at the back and are retried later");
});

test("a 404 whose body is an NVD envelope is a real zero-match answer, not a failure", async (t) => {
  const previousKey = process.env.NVD_API_KEY;
  process.env.NVD_API_KEY = VALID_KEY;
  const previousOffline = process.env.WSMD_OFFLINE;
  process.env.WSMD_OFFLINE = "1";
  const cacheDir = tempCacheDir();
  t.after(() => {
    if (previousKey === undefined) delete process.env.NVD_API_KEY;
    else process.env.NVD_API_KEY = previousKey;
    if (previousOffline === undefined) delete process.env.WSMD_OFFLINE;
    else process.env.WSMD_OFFLINE = previousOffline;
    rmSync(cacheDir, { recursive: true, force: true });
  });

  const asked = [];
  const http404 = {
    cacheDir,
    async get(url) {
      asked.push(new URL(url).searchParams.get("keywordSearch"));
      return {
        body: null, from: "none", fetched_at: null, error: "HTTP 404", status: 404,
        bodyText: '{"resultsPerPage":0,"totalResults":0,"format":"NVD_CVE","vulnerabilities":[]}',
      };
    },
    async getBinary() {
      return { body: null, from: "none", fetched_at: null, error: "HTTP 404", status: 404 };
    },
  };
  const names = [{ name: "whatsapp", wanted: new Set(["whatsapp"]) }];

  const first = await lookupProducts({
    http: http404, config: configWith(null), cacheDir, names, ttlMs: 24 * 60 * 60 * 1000, force: false,
  });
  assert.equal(first.stats.not_found, 1, "an envelope 404 counts as not_found");
  assert.equal(first.stats.failed_404, 0, "and NOT as a failure");
  assert.equal(first.stats.pending, 0, "a real negative closes the product");

  asked.length = 0;
  await lookupProducts({
    http: http404, config: configWith(null), cacheDir, names, ttlMs: 24 * 60 * 60 * 1000, force: false,
  });
  assert.deepEqual(asked, [], "within the not-found TTL the negative is trusted: no retry this run");
});

test("a 404 with an empty body (key flakiness) stays transient and is retried", async (t) => {
  const previousKey = process.env.NVD_API_KEY;
  process.env.NVD_API_KEY = VALID_KEY;
  const previousOffline = process.env.WSMD_OFFLINE;
  process.env.WSMD_OFFLINE = "1";
  const cacheDir = tempCacheDir();
  t.after(() => {
    if (previousKey === undefined) delete process.env.NVD_API_KEY;
    else process.env.NVD_API_KEY = previousKey;
    if (previousOffline === undefined) delete process.env.WSMD_OFFLINE;
    else process.env.WSMD_OFFLINE = previousOffline;
    rmSync(cacheDir, { recursive: true, force: true });
  });

  const http404empty = {
    cacheDir,
    async get() {
      return { body: null, from: "none", fetched_at: null, error: "HTTP 404", status: 404, bodyText: "" };
    },
    async getBinary() {
      return { body: null, from: "none", fetched_at: null, error: "HTTP 404", status: 404 };
    },
  };
  const result = await lookupProducts({
    http: http404empty, config: configWith(null), cacheDir,
    names: [{ name: "git", wanted: new Set(["git"]) }],
    ttlMs: 24 * 60 * 60 * 1000, force: false,
  });
  assert.equal(result.stats.failed_404, 1, "an empty-body 404 is the flakiness shape: transient");
  assert.equal(result.stats.not_found, 0, "it is not cached as a negative");
  assert.equal(result.stats.pending, 1, "the product stays open for a retry");
});

test("mergeProductIndexes: primary records win, the fallback only adds missed ids", async () => {
  const { mergeProductIndexes } = await import("../dist/modules/cves/index.js");
  const rec = (cve_id, cvss) => ({ cve_id, product: "git", vendor: null, summary: null, published: null, cvss, range_from: null, range_below: null, fixed_version: null });
  const primary = {
    byProduct: new Map([["git", [rec("CVE-2024-1", 9.8)]]]),
    byCve: new Map([["CVE-2024-1", rec("CVE-2024-1", 9.8)]]),
    totalCves: 1,
    products: 1,
    fetched_at: null,
    from: "cache",
  };
  const fallback = {
    byProduct: new Map([["git", [rec("CVE-2024-1", null), rec("CVE-2024-2", 5)]]]),
    byCve: new Map([["CVE-2024-1", rec("CVE-2024-1", null)], ["CVE-2024-2", rec("CVE-2024-2", 5)]]),
    totalCves: 2,
    products: 1,
    fetched_at: null,
    from: "cache",
  };
  const merged = mergeProductIndexes(primary, fallback);
  assert.deepEqual(merged.byProduct.get("git").map((r) => r.cve_id), ["CVE-2024-1", "CVE-2024-2"], "the missed id is added");
  assert.equal(merged.byProduct.get("git")[0].cvss, 9.8, "the primary record wins a collision");
  assert.equal(merged.byCve.get("CVE-2024-1").cvss, 9.8, "byCve keeps the enriched record");
  assert.equal(merged.totalCves, 2, "deduplicated by CVE id");
});

test("postCached answers from disk within the TTL and writes one file per body", async (t) => {
  const { createServer } = await import("node:http");
  const previous = process.env.WSMD_OFFLINE;
  const cacheDir = tempCacheDir();
  let calls = 0;
  const server = createServer((req, res) => {
    calls += 1;
    res.writeHead(200, { "content-type": "application/json" });
    res.end('{"results":[{"vulns":[{"id":"GHSA-4v2v-hcxm-r7wc"}]}]}');
  });
  await new Promise((resolve) => server.listen(0, "127.0.0.1", resolve));
  const url = `http://127.0.0.1:${String(server.address().port)}/v1/querybatch`;
  const body = '{"queries":[]}';
  t.after(() => {
    if (previous === undefined) delete process.env.WSMD_OFFLINE;
    else process.env.WSMD_OFFLINE = previous;
    server.close();
    rmSync(cacheDir, { recursive: true, force: true });
  });

  delete process.env.WSMD_OFFLINE;
  const first = await postCached(cacheDir, url, body, 60_000);
  assert.equal(first.from, "network");
  assert.equal(calls, 1);

  // Inside the TTL the answer comes off disk: the server is not asked a second time.
  const warm = await postCached(cacheDir, url, body, 60_000);
  assert.equal(warm.from, "cache");
  assert.equal(calls, 1);

  // Expired plus offline still answers, and labels the answer stale instead of fresh.
  process.env.WSMD_OFFLINE = "1";
  const expired = await postCached(cacheDir, url, body, 0);
  assert.equal(expired.from, "stale_cache");
  assert.equal(expired.error, "offline");

  // A different body is a different key, so it must not pick up the first body's cached answer.
  const other = await postCached(cacheDir, url, '{"queries":[{"package":{"name":"git"}}]}', 60_000);
  assert.equal(other.from, "none");
  assert.equal(readdirSync(cacheDir).length, 1, "the offline attempt wrote no second entry");
});
