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

  assert.equal(result.stats.deferred, 2, "the budget is visible instead of silent");
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
