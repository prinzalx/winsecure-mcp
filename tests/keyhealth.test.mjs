import assert from "node:assert/strict";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { test } from "node:test";

import { lookupProducts, nvdKeyHealth, recordKeyProbe, __testing } from "../dist/modules/cves/products.js";
import { buildCompleteness } from "../dist/modules/cves/index.js";

const VALID_KEY = "0123456789abcdef0123456789abcdef";
const UUID_KEY = "BB3F4D66-38C9-F111-8377-129478FCB64D";

function configWith(nvdApiKey, extra = {}) {
  return {
    settings: { nvdApiKey, nvdProductsPerRun: 400, nvdMaxPages: 5, httpTimeoutMs: 15000, ...extra },
    path: "<test>",
    save() {},
  };
}

function tempCacheDir() {
  return mkdtempSync(join(tmpdir(), "wsmd-keyhealth-"));
}

/** An {@link Http} stand-in recording url AND headers, answering per product from `handler`. */
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
 * Run one keyed lookup against a mocked NVD with the environment isolated.
 *
 * `WSMD_OFFLINE` is cleared on purpose: the {@link Http} below is a mock, so there is no real
 * network to switch off, and the offline flag would additionally no-op the throttle — which is
 * exactly what these tests assert on (the queue pause a key rejection sets).
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

test("a 200 answer fills the cache, drops deferred to 0, and completeness reads complete", async (t) => {
  const cacheDir = tempCacheDir();
  t.after(() => { __testing.reset(cacheDir); rmSync(cacheDir, { recursive: true, force: true }); });

  const envelope = {
    totalResults: 1,
    vulnerabilities: [{
      cve: {
        id: "CVE-2024-1234",
        lastModified: "2026-01-01T00:00:00.000Z",
        metrics: { cvssMetricV31: [{ cvssData: { baseScore: 7.5 } }] },
        configurations: [{ nodes: [{ cpeMatch: [{ criteria: "cpe:2.3:a:git-scm:git:*:*:*:*:*:*:*:*", vulnerable: true, versionEndExcluding: "2.50.0" }] }] }],
      },
    }],
  };
  // The cpeMatch product must be the queried one, or `nvdRecords` drops the record again.
  const http = mockHttp(cacheDir, (product) => ({
    body: JSON.stringify({
      ...envelope,
      vulnerabilities: [{
        cve: {
          ...envelope.vulnerabilities[0].cve,
          configurations: [{ nodes: [{ cpeMatch: [{ criteria: `cpe:2.3:a:vend:${product}:*:*:*:*:*:*:*:*`, vulnerable: true, versionEndExcluding: "2.50.0" }] }] }],
        },
      }],
    }),
    from: "network", fetched_at: new Date().toISOString(),
  }));
  const names = [
    { name: "git", wanted: new Set(["git"]) },
    { name: "sevenzip", wanted: new Set(["sevenzip"]) },
  ];
  const result = await keyedRun(cacheDir, http, names);
  assert.equal(result.stats.done, 2, "both products answered with a 200");
  assert.equal(result.stats.deferred, 0, "the queue emptied in one run");
  assert.equal(result.stats.products_cached, 2, "products_cached rose — the cache is no longer stuck at 0");

  const completeness = buildCompleteness(result.stats, false, "checked");
  assert.equal(completeness.status, "complete");
  assert.equal(completeness.needs_attention, undefined, "a healthy run asks for no attention");

  // A 200 also means NVD is answering: the breaker must not sit open over a working endpoint.
  assert.equal(nvdKeyHealth(cacheDir).tripped, false);
});

test("recordKeyProbe re-validates: rejected pauses, a later valid probe resumes (hot key change)", async (t) => {
  const cacheDir = tempCacheDir();
  t.after(() => { __testing.reset(cacheDir); rmSync(cacheDir, { recursive: true, force: true }); });

  // The probe flow of the dashboard POST and of startup: validate → record. A rejected key puts
  // the queue on a long pause …
  recordKeyProbe(cacheDir, { status: "rejected", error: "NVD rejected the key (HTTP 404: Invalid apiKey.)" }, 900_000);
  assert.equal(nvdKeyHealth(cacheDir).status, "rejected");
  assert.ok(
    __testing.queues(cacheDir).some((q) => q.throttle.pausedUntilMs() > Date.now()),
    "a rejected probe pauses the drain",
  );

  // … and pasting a good key without a restart (the hot key change) validates again and resumes.
  recordKeyProbe(cacheDir, { status: "valid" }, 900_000);
  assert.equal(nvdKeyHealth(cacheDir).status, "valid");
  assert.equal(nvdKeyHealth(cacheDir).tripped, false, "a new key clears the circuit breaker");
  for (const q of __testing.queues(cacheDir)) assert.equal(q.throttle.pausedUntilMs(), 0, "every pause lifted — the drain runs again");
});

test("a rejected key paces the drain to the keyless window (5 per 30 s default)", async (t) => {
  const cacheDir = tempCacheDir();
  t.after(() => { __testing.reset(cacheDir); rmSync(cacheDir, { recursive: true, force: true }); });

  const http = mockHttp(cacheDir, () => ({
    body: null, from: "none", fetched_at: null, error: "HTTP 404", status: 404, bodyText: "", message: "Invalid apiKey.",
  }));
  const names = [{ name: "git", wanted: new Set(["git"]) }, { name: "edge", wanted: new Set(["edge"]) }];

  // First run discovers the rejection through a product lookup.
  await keyedRun(cacheDir, http, names);
  http.calls.length = 0;
  // The follow-up run must move at the keyless interval: 30_000 / 5 = 6_000 ms spacing.
  await keyedRun(cacheDir, http, names);
  const keyless = __testing.queues(cacheDir).find((q) => q.throttleIntervalMs === 6_000);
  assert.ok(keyless !== undefined, "a queue paced at the documented keyless window exists");
});
