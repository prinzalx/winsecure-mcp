import assert from "node:assert/strict";
import { mkdtempSync, readdirSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { test } from "node:test";

import {
  looksLikeNvdKey,
  lookupProducts,
  mergeRecords,
  nvdKeyHealth,
  osvCveId,
  recordKeyProbe,
  resolveNvdKey,
  validateNvdKey,
  __testing,
} from "../dist/modules/cves/products.js";
import { buildCompleteness, productNames } from "../dist/modules/cves/index.js";
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
  assert.equal(check.status, "rejected");
  assert.match(String(check.error), /valid NVD key format/);
  assert.equal((await validateNvdKey("")).status, "rejected");
});

test("validateNvdKey sends the key as the apiKey HEADER, never as a query parameter", async () => {
  const previous = globalThis.fetch;
  const requests = [];
  globalThis.fetch = async (url, init) => {
    requests.push({ url: String(url), headers: init?.headers ?? {} });
    return new Response('{"totalResults":0,"vulnerabilities":[]}', { status: 200, headers: { "content-type": "application/json" } });
  };
  try {
    const check = await validateNvdKey(UUID_KEY, 5000);
    assert.equal(check.status, "valid");
    assert.equal(requests.length, 1, "exactly one probe request");
    assert.equal(new URL(requests[0].url).searchParams.get("apiKey"), null, "the key must not ride in the query string");
    assert.equal(requests[0].headers.apiKey, UUID_KEY, "NVD API 2.0 wants the key in the `apiKey` header");
  } finally {
    globalThis.fetch = previous;
  }
});

test("a probe answered 429 leaves the key unknown, never rejected", async () => {
  const previous = globalThis.fetch;
  globalThis.fetch = async () => new Response("error code: 1015", { status: 429 });
  try {
    const check = await validateNvdKey(UUID_KEY, 5000);
    assert.equal(check.status, "unknown", "a rate limit says nothing about the key's validity");
  } finally {
    globalThis.fetch = previous;
  }
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

// ---------------------------------------------------------------------------
// v0.6.6: the 404 shapes split apart, the key gets a health state, the breaker
// ---------------------------------------------------------------------------

/**
 * An {@link Http} stand-in that records every request (url AND headers) and answers each product
 * with what the handler returns — the mocked NVD client the v0.6.6 tests need, because the
 * failure class now lives in the `message` response header, which `offlineHttp` cannot carry.
 */
function mockHttp(cacheDir, handler) {
  const calls = [];
  return {
    cacheDir,
    calls,
    async get(url, ttlMs, headers) {
      calls.push({ url: String(url), headers: headers ?? {} });
      const product = new URL(String(url)).searchParams.get("keywordSearch");
      return handler(product, calls.length);
    },
    async getBinary() {
      return { body: null, from: "none", fetched_at: null, error: "offline" };
    },
  };
}

/**
 * Run one keyed lookup against a mocked NVD, with the environment isolated and maps reset.
 *
 * `WSMD_OFFLINE` is cleared: the {@link Http} above is a mock (no real network to switch off) and
 * the offline flag would no-op the throttle, which is exactly what these tests assert on.
 */
async function keyedRun(cacheDir, http, names, extra = {}, key = VALID_KEY) {
  const previousKey = process.env.NVD_API_KEY;
  if (key === null) delete process.env.NVD_API_KEY;
  else process.env.NVD_API_KEY = key;
  const previousOffline = process.env.WSMD_OFFLINE;
  delete process.env.WSMD_OFFLINE;
  try {
    return await lookupProducts({
      http,
      config: configWith(null, extra),
      cacheDir,
      names,
      ttlMs: 24 * 60 * 60 * 1000,
      force: false,
    });
  } finally {
    if (previousKey === undefined) delete process.env.NVD_API_KEY;
    else process.env.NVD_API_KEY = previousKey;
    if (previousOffline === undefined) delete process.env.WSMD_OFFLINE;
    else process.env.WSMD_OFFLINE = previousOffline;
  }
}

test("the product query sends the key as apiKey HEADER and not in the query string (v0.6.6 diagnosis)", async (t) => {
  const cacheDir = tempCacheDir();
  t.after(() => { __testing.reset(cacheDir); rmSync(cacheDir, { recursive: true, force: true }); });

  const http = mockHttp(cacheDir, () => ({
    body: '{"totalResults":0,"vulnerabilities":[]}', from: "network", fetched_at: new Date().toISOString(),
  }));
  const result = await keyedRun(cacheDir, http, [{ name: "git", wanted: new Set(["git"]) }]);

  assert.equal(result.stats.mode, "nvd-keyed");
  assert.equal(http.calls.length, 1);
  assert.equal(http.calls[0].headers.apiKey, VALID_KEY, "the key must ride in the `apiKey` header");
  assert.equal(new URL(http.calls[0].url).searchParams.get("apiKey"), null, "…and not in the query string (NVD 404s it there)");
});

test("a 404 with message 'Invalid apiKey.' marks the key rejected, pauses the drain, and switches lookups keyless", async (t) => {
  const cacheDir = tempCacheDir();
  t.after(() => { __testing.reset(cacheDir); rmSync(cacheDir, { recursive: true, force: true }); });

  // NVD's exact live answer for a key it refuses (verified 2026-10-16): HTTP 404, EMPTY body,
  // reason only in the `message` header.
  const http = mockHttp(cacheDir, () => ({
    body: null, from: "none", fetched_at: null, error: "HTTP 404", status: 404, bodyText: "", message: "Invalid apiKey.",
  }));
  const names = [
    { name: "git", wanted: new Set(["git"]) },
    { name: "edge", wanted: new Set(["edge"]) },
  ];
  // The key-rejection pause stays far below the call's 20 s budget here, so one call still
  // reaches both products and the assertions below see a complete picture of the run.
  const first = await keyedRun(cacheDir, http, names, { nvdBreakerPauseMs: 3_000 });

  assert.equal(first.stats.key_rejected, 2, "both lookups classify as key_rejected, not as generic 404 failures");
  assert.equal(first.stats.failed_404, 0, "a key rejection is NOT counted with the unexplained 404s");
  assert.equal(first.stats.key_status, "rejected", "the health state flips to rejected");
  assert.equal(nvdKeyHealth(cacheDir).status, "rejected");
  assert.ok(
    __testing.queues(cacheDir)[0].throttle.pausedUntilMs() > Date.now(),
    "the drain is paused — no retry storm against an endpoint that refuses the key",
  );

  const completeness = buildCompleteness(first.stats, false, "checked");
  assert.ok(completeness.reasons.includes("nvd_key_rejected"), "an agent can tell a config problem from a slow warm-up");
  assert.match(completeness.hint, /key/i, "the hint says what to do about the key");
  assert.equal(completeness.needs_attention, true);

  // Task 4: with the key rejected, further requests go out KEYLESS (no apiKey header) so progress
  // stays possible; the pacing moves to the keyless queue.
  http.calls.length = 0;
  // One product only: the rejection pacing is now the keyless window (6 s spacing), and what
  // matters here is that the request goes out WITHOUT the rejected key, not how many do.
  const second = await keyedRun(cacheDir, http, [names[0]], { nvdBreakerPauseMs: 3_000 });
  assert.ok(http.calls.length > 0, "the second run still asks NVD — progress continues at the keyless rate");
  for (const call of http.calls) assert.equal(call.headers.apiKey, undefined, "requests go out without the rejected key");
  assert.ok(second.stats.key_status === "rejected");
});

test("a 404 with message 'Invalid parameter: …' is request_invalid and retries stay bounded", async (t) => {
  const cacheDir = tempCacheDir();
  t.after(() => { __testing.reset(cacheDir); rmSync(cacheDir, { recursive: true, force: true }); });

  const http = mockHttp(cacheDir, () => ({
    body: null, from: "none", fetched_at: null, error: "HTTP 404", status: 404, bodyText: "", message: "Invalid parameter: keywordSearch.",
  }));
  const names = [{ name: "git", wanted: new Set(["git"]) }];
  const first = await keyedRun(cacheDir, http, names, { nvdRequestInvalidMaxAttempts: 2 });
  assert.equal(first.stats.request_invalid, 1);
  assert.equal(first.stats.failed_404, 0, "an invalid request is not the unexplained 404 class");
  assert.equal(first.stats.deferred, 1, "the first failure stays open for one retry");

  const completeness = buildCompleteness(first.stats, false, "checked");
  assert.ok(completeness.reasons.includes("nvd_requests_invalid"));

  // After the bounded retries the product CLOSES OUT: the third call must not ask again forever.
  await keyedRun(cacheDir, http, names, { nvdRequestInvalidMaxAttempts: 2 });
  http.calls.length = 0;
  const third = await keyedRun(cacheDir, http, names, { nvdRequestInvalidMaxAttempts: 2 });
  assert.equal(http.calls.length, 0, "attempts beyond the bound are not retried — no endless rotation");
  assert.equal(third.stats.deferred, 0, "the closed-out product leaves the queue, so deferred can reach 0");
});

test("a 404 with an NVD envelope stays a real not_found with TTL (v0.6.5 semantics preserved)", async (t) => {
  const cacheDir = tempCacheDir();
  t.after(() => { __testing.reset(cacheDir); rmSync(cacheDir, { recursive: true, force: true }); });

  const http = mockHttp(cacheDir, () => ({
    body: null, from: "none", fetched_at: null, error: "HTTP 404", status: 404,
    bodyText: '{"resultsPerPage":0,"totalResults":0,"format":"NVD_CVE","vulnerabilities":[]}',
  }));
  const names = [{ name: "whatsapp", wanted: new Set(["whatsapp"]) }];
  const first = await keyedRun(cacheDir, http, names);
  assert.equal(first.stats.not_found, 1);
  http.calls.length = 0;
  await keyedRun(cacheDir, http, names);
  assert.equal(http.calls.length, 0, "the negative is trusted inside its TTL");
});

test("the circuit breaker pauses the drain after N consecutive failures without a single 200", async (t) => {
  const cacheDir = tempCacheDir();
  t.after(() => { __testing.reset(cacheDir); rmSync(cacheDir, { recursive: true, force: true }); });

  // 404 without message and without envelope: the shape that hid the empty cache for 7 runs.
  const http = mockHttp(cacheDir, () => ({
    body: null, from: "none", fetched_at: null, error: "HTTP 404", status: 404, bodyText: "",
  }));
  const names = Array.from({ length: 4 }, (_, i) => ({ name: `p${String(i)}`, wanted: new Set([`p${String(i)}`]) }));
  const result = await keyedRun(cacheDir, http, names, { nvdBreakerThreshold: 3 });
  assert.equal(nvdKeyHealth(cacheDir).tripped, true, "3 failures, no 200 → breaker open");
  assert.equal(result.stats.breaker_tripped, true);
  const completeness = buildCompleteness(result.stats, false, "checked");
  assert.ok(completeness.reasons.includes("nvd_all_lookups_failing"), "an agent sees 'every lookup fails', not 'few hits'");
});

