import { mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { join } from "node:path";

import { normName } from "../../utils/matching.js";
import { NvdThrottle } from "../../utils/throttle.js";
import { postCached, type CachedFetch, type Http } from "../../utils/net.js";
import type { ConfigStore } from "../../config.js";
import type { CveRecord } from "./feeds.js";

/**
 * How the CVE answers of a run were obtained.
 *
 * The distinction is the point of the whole lookup layer: `nvd-keyed` answers from the full NVD
 * corpus on day one, while `keyless-osv+cached` answers from an OSV batch plus whatever the local
 * cache already holds, which is genuinely thinner. A reader must never be able to confuse "no
 * vulnerabilities" with "the answer was thin", so the mode travels in every `check_cves` result and
 * in the dashboard.
 */
export type LookupMode = "nvd-keyed" | "keyless-osv+cached";

const NVD_API = "https://services.nvd.nist.gov/rest/json/cves/2.0";
const OSV_BATCH = "https://api.osv.dev/v1/querybatch";

/** Where an API key came from. `null` means no key is configured at all. */
export type KeySource = "env" | "config" | "file" | null;

export interface NvdKeyState {
  key: string | null;
  source: KeySource;
}

/**
 * The NVD key, environment first.
 *
 * `NVD_API_KEY` wins over the key saved in the dashboard, because an operator who exports the
 * variable deliberately (a systemd unit, a container secret) must not be overridden by a stale
 * value in a JSON file they may not even know about. Last comes a plain-text `nvd_api_key` file
 * in the data directory, so a host whose dashboard is unreachable can still run keyed without an
 * environment (a single line with the key).
 */
export function resolveNvdKey(config: ConfigStore): NvdKeyState {
  const env = process.env.NVD_API_KEY;
  if (typeof env === "string" && env.trim() !== "") return { key: env.trim(), source: "env" };
  const saved = config.settings.nvdApiKey;
  if (typeof saved === "string" && saved.trim() !== "") return { key: saved.trim(), source: "config" };
  try {
    // Read fresh on every call: a file dropped in while the server runs must be picked up.
    const fileKey = readFileSync(join(config.settings.dataDir, "nvd_api_key"), "utf8").trim();
    if (fileKey !== "") return { key: fileKey, source: "file" };
  } catch {
    // No file, or unreadable: same as no key.
  }
  return { key: null, source: null };
}

/**
 * Format of an NVD key: NVD handed out 32 hex characters for years and now issues UUIDs with
 * dashes, so both are accepted. Anything clearly shorter or with foreign characters cannot be one.
 */
export function looksLikeNvdKey(candidate: string): boolean {
  return /^[0-9a-f]{8}-?[0-9a-f]{4}-?[0-9a-f]{4}-?[0-9a-f]{4}-?[0-9a-f]{12}$/i.test(candidate.trim());
}

export interface KeyValidation {
  valid: boolean;
  error?: string;
}

/**
 * Live test of a key against NVD itself, bypassing the disk cache: it must cost no cached answer
 * and answer even when a probe ran a second ago.
 *
 * NVD answers an unknown or malformed key with HTTP 401, which is the only trustworthy check — a
 * purely local format test would accept a typo'd key and then every product query would fail.
 */
export async function validateNvdKey(key: string, timeoutMs = 15_000): Promise<KeyValidation> {
  const trimmed = key.trim();
  if (trimmed === "") return { valid: false, error: "no key given" };
  if (!looksLikeNvdKey(trimmed)) {
    return { valid: false, error: "not a valid NVD key format (32 hex chars or a UUID)" };
  }
  try {
    const res = await fetch(`${NVD_API}?keywordSearch=winsecure-mcp-key-probe&resultsPerPage=1&apiKey=${encodeURIComponent(trimmed)}`, {
      headers: { accept: "application/json" },
      signal: AbortSignal.timeout(timeoutMs),
    });
    if (res.ok) return { valid: true };
    const detail = await res.text().catch(() => "");
    if (res.status === 401) return { valid: false, error: "NVD rejected the key (HTTP 401)" };
    // NVD currently answers a freshly issued key with 404 + "Invalid parameter: apiKey." while the
    // activation has not propagated; like a 5xx this says nothing about the key, so it must not
    // be reported as wrong, and the key stays usable.
    if (res.status === 404) return { valid: true };
    // A 5xx or a rate-limit answer says nothing about the key, so it must not be reported as wrong.
    return { valid: false, error: `NVD answered HTTP ${String(res.status)}${detail ? `: ${detail.slice(0, 80)}` : ""}` };
  } catch (cause) {
    return { valid: false, error: cause instanceof Error ? cause.message : String(cause) };
  }
}

// ---------------------------------------------------------------------------
// Per-product cache
// ---------------------------------------------------------------------------

/** One cached answer for one product name. This — not a CVE — is the unit of storage now. */
interface ProductCacheEntry {
  /** The name as it was queried, for display. */
  name: string;
  /** Records NVD reported for this product, already trimmed to matching products. */
  records: CveRecord[];
  /** Newest `lastModified` seen; the start of the next incremental query. */
  last_modified: string | null;
  fetched_at: string;
  source: "nvd" | "osv";
  /** True when the answer was cut at the page cap rather than delivered whole. */
  truncated: boolean;
  /**
   * Set when NVD answered a full query with zero results: a genuine negative. Negative entries are
   * only trusted for the short not-found TTL (since v0.6.3), because an NVD outage that presents
   * as "no results" must not silence a product for a whole day.
   */
  not_found_at?: string | null;
}

interface ProductCacheFile {
  schema: number;
  products: Record<string, ProductCacheEntry>;
}

export interface ProductLookupStats {
  mode: LookupMode;
  /** Product names the cache answered for (fresh or stale). */
  products_cached: number;
  /** Product names this run actually asked NVD/OSV about. */
  refreshed: number;
  /** Products the run wanted to refresh but the per-run budget did not cover. */
  deferred: number;
  fetched_at: string | null;
  errors: string[];
  /** Every product name the run was asked about. */
  products_total: number;
  /**
   * Products left without a fresh usable answer after this run (transient failures included, since
   * a failed lookup is not done). The completeness judgement in `check_cves` reads this number.
   */
  pending: number;
  /** Products whose lookup ended in HTTP 429 (the rate limit was hit). */
  failed_429: number;
  /**
   * Products whose lookup ended in HTTP 404. With a key set NVD answers 404 flakily (observed
   * live: an empty body with `Invalid parameter: apiKey.`), so a 404 is a transient failure here,
   * not a "no such CVE" statement, and never cached as one.
   */
  failed_404: number;
  /** Products whose lookup failed for another transient reason (5xx, timeout, network, offline). */
  failed_other: number;
  /** Products freshly answered with a negative (zero results) entry this run. */
  not_found: number;
  /** True when the per-call time budget ran out and the queue drain continues in the background. */
  warm_up_running: boolean;
}

/**
 * The per-product CVE answers on disk, replacing the global corpus index.
 *
 * Expected size is one entry per installed program rather than one per CVE, which is the whole
 * point of the product-centric model: the questions this server asks are about ~350 programs, not
 * about 290,000 CVEs.
 */
class ProductCache {
  private readonly file: string;
  private data: ProductCacheFile;

  constructor(cacheDir: string) {
    this.file = join(cacheDir, "products.json");
    this.data = { schema: 1, products: {} };
    try {
      const raw = JSON.parse(readFileSync(this.file, "utf8")) as Partial<ProductCacheFile>;
      if (raw && typeof raw.products === "object" && raw.products !== null) {
        this.data = { schema: 1, products: raw.products as Record<string, ProductCacheEntry> };
      }
    } catch {
      // A missing or unreadable cache simply means everything is fetched on the next run.
    }
  }

  get(name: string): ProductCacheEntry | undefined {
    return this.data.products[normName(name)];
  }

  set(name: string, entry: ProductCacheEntry): void {
    this.data.products[normName(name)] = entry;
  }

  /**
   * Whether an entry may answer for the product instead of a network fetch.
   *
   * Two rules came out of the v0.6.2 field runs (task 2): keyed mode demands a `source: "nvd"`
   * entry — a keyless OSV entry carries bare CVE ids without CVSS or ranges, and counting it as
   * fresh is exactly what left `refreshed: 0` and `nvd_enriched: 0` after a key was added — and a
   * `not_found` negative is only trusted for the short not-found TTL, so a product silenced by an
   * NVD oddity gets asked again soon. A product that failed transiently has no entry at all here
   * and is retried, never treated as done.
   */
  isFresh(name: string, ttlMs: number, keyed: boolean, notFoundTtlMs: number, force: boolean): boolean {
    if (force) return false;
    const entry = this.get(name);
    if (!entry) return false;
    if (keyed && entry.source !== "nvd") return false;
    const at = entry.not_found_at ?? entry.fetched_at;
    const age = Date.now() - Date.parse(at);
    if (!Number.isFinite(age) || age < 0) return false;
    return age < (entry.not_found_at ? Math.min(ttlMs, notFoundTtlMs) : ttlMs);
  }

  get size(): number {
    return Object.keys(this.data.products).length;
  }

  names(): string[] {
    return Object.values(this.data.products).map((p) => p.name);
  }

  newestFetchedAt(): string | null {
    let newest: string | null = null;
    for (const p of Object.values(this.data.products)) if ((p.fetched_at ?? "") > (newest ?? "")) newest = p.fetched_at;
    return newest;
  }

  save(): void {
    try {
      mkdirSync(join(this.file, ".."), { recursive: true });
      writeFileSync(this.file, JSON.stringify(this.data), "utf8");
    } catch {
      // An unwritable cache costs the next run its fetches, nothing more.
    }
  }
}

// ---------------------------------------------------------------------------
// NVD answer parsing
// ---------------------------------------------------------------------------

interface NvdAffected {
  product?: string;
  vendor?: string;
  versions?: { version?: string; status?: string; lessThan?: string }[];
}

interface NvdCveJson {
  id?: string;
  published?: string;
  lastModified?: string;
  descriptions?: { value?: string; lang?: string }[];
  metrics?: Record<string, { cvssData?: { baseScore?: number } }[]>;
  configurations?: {
    nodes?: {
      cpeMatch?: { criteria?: string; vulnerable?: boolean; versionStartIncluding?: string; versionEndExcluding?: string }[];
    }[];
  }[];
}

/**
 * The records one NVD API 2.0 answer contributes for one queried product name.
 *
 * The API returns whole CVE documents, most of which mention several products (a Chrome CVE often
 * lists Safari too). Only the products whose normalised name matches one of the queried candidate
 * names are kept, so the cache stays one entry per installed program instead of a corpus copy. The
 * affected range comes from the CPE match (`versionEndExcluding`) when present, which is what the
 * v0.5.x version verdict reads.
 */
function nvdRecords(doc: NvdCveJson, wanted: Set<string>): CveRecord[] {
  const id = String(doc.id ?? "");
  if (id === "") return [];

  const metrics = doc.metrics ?? {};
  const score =
    metrics.cvssMetricV40?.[0]?.cvssData?.baseScore ?? metrics.cvssMetricV31?.[0]?.cvssData?.baseScore ?? null;

  const descriptions = doc.descriptions ?? [];
  const english = descriptions.find((d) => String(d.lang ?? "").toLowerCase().startsWith("en"));
  const summary = String((english ?? descriptions[0])?.value ?? "").replace(/\s+/g, " ").trim().slice(0, 400) || null;

  const published = doc.published ? `${String(doc.published).slice(0, 10)}T00:00:00Z` : null;

  const out: CveRecord[] = [];
  const seenProducts = new Set<string>();

  for (const cfg of doc.configurations ?? []) {
    for (const node of cfg.nodes ?? []) {
      for (const m of node.cpeMatch ?? []) {
        if (m.vulnerable === false) continue;
        const product = cpeProduct(String(m.criteria ?? ""));
        if (product === "") continue;
        const key = normName(product);
        if (!wanted.has(key) || seenProducts.has(key)) continue;
        seenProducts.add(key);
        out.push({
          cve_id: id,
          product: key,
          vendor: null,
          summary,
          published,
          cvss: typeof score === "number" ? score : null,
          range_from: m.versionStartIncluding ?? null,
          range_below: m.versionEndExcluding ?? null,
          fixed_version: m.versionEndExcluding ?? null,
        });
      }
    }
  }

  // An answer with no CPE match carries no version information at all. The CVE is still worth
  // carrying — dropping it would trade a false positive for a false negative in a security tool —
  // and the verdict records it as an unverified match.
  if (out.length === 0) {
    const mentioned = new Set<string>();
    for (const cfg of doc.configurations ?? []) {
      for (const node of cfg.nodes ?? []) {
        for (const m of node.cpeMatch ?? []) mentioned.add(normName(cpeProduct(String(m.criteria ?? ""))));
      }
    }
    if (mentioned.size === 0) {
      for (const name of wanted) {
        out.push({
          cve_id: id,
          product: name,
          vendor: null,
          summary,
          published,
          cvss: typeof score === "number" ? score : null,
          range_from: null,
          range_below: null,
          fixed_version: null,
        });
      }
    }
  }
  return out;
}

/** The product field of a CPE 2.3 uri (`cpe:2.3:a:vendor:product:version:...`). */
function cpeProduct(criteria: string): string {
  const parts = criteria.split(":");
  return parts.length > 4 ? parts[4] ?? "" : "";
}

function newestLastModified(vulnerabilities: { cve?: NvdCveJson }[]): string | null {
  let newest: string | null = null;
  for (const v of vulnerabilities) {
    const at = v.cve?.lastModified;
    if (typeof at === "string" && at > (newest ?? "")) newest = at;
  }
  return newest;
}

// NVD's own paging maximum; a bigger page means fewer requests against a strict rate limit.
const NVD_PAGE_SIZE = 2000;

/** NVD rejects a `lastModStartDate`/`lastModEndDate` window wider than 120 days. */
const MAX_LASTMOD_WINDOW_DAYS = 120;


/**
 * One product's CVE list from NVD API 2.0, paged, optionally incremental.
 *
 * `keywordSearch` is used rather than a CPE match because the inventory only has a Windows display
 * name ("Microsoft Edge"), no vendor; the local product filter then decides what the entry keeps.
 * When the cache already knows the product, only changes since its `last_modified` are asked for,
 * which is what keeps a warm run cheap.
 */
async function nvdProductQuery(
  http: Http,
  opts: {
    name: string;
    wanted: Set<string>;
    key: string | null;
    sinceModified: string | null;
    maxPages: number;
    /** Shared pacing gate; every page request goes through it (task 1, v0.6.3). */
    throttle: NvdThrottle;
  },
): Promise<{
  records: CveRecord[];
  lastModified: string | null;
  truncated: boolean;
  error?: string;
  /** HTTP status of the failed request, when one failed (used for the failure classes). */
  status?: number;
  retryAfterMs?: number;
}> {
  const collected: CveRecord[] = [];
  let lastModified: string | null = null;
  let error: string | undefined;

  for (let page = 0; page < opts.maxPages; page += 1) {
    const params = new URLSearchParams({
      keywordSearch: opts.name,
      resultsPerPage: String(NVD_PAGE_SIZE),
      startIndex: String(page * NVD_PAGE_SIZE),
    });
    if (opts.sinceModified) {
      // NVD wants these without the milliseconds; the window must stay inside its 120-day limit.
      const start = opts.sinceModified.replace(/\.\d+Z$/, "Z");
      const startDays = (Date.now() - Date.parse(start)) / 86_400_000;
      if (Number.isFinite(startDays) && startDays <= MAX_LASTMOD_WINDOW_DAYS) {
        params.set("lastModStartDate", start);
        params.set("lastModEndDate", new Date().toISOString().replace(/\.\d+Z$/, "Z"));
      }
    }
    if (opts.key) params.set("apiKey", opts.key);

    await opts.throttle.acquire();
    const res = await http.get(`${NVD_API}?${params.toString()}`, 0);
    if (!res.body) {
      error = res.error ?? "no answer";
      return { records: collected, lastModified, truncated: page > 0, error, status: res.status, retryAfterMs: res.retryAfterMs };
    }
    let parsed: { totalResults?: number; vulnerabilities?: { cve?: NvdCveJson }[] };
    try {
      parsed = JSON.parse(res.body) as typeof parsed;
    } catch (cause) {
      error = `NVD answer was not valid JSON: ${String(cause)}`;
      break;
    }
    const vulns = parsed.vulnerabilities ?? [];
    for (const v of vulns) collected.push(...nvdRecords(v.cve ?? {}, opts.wanted));
    lastModified = newestLastModified(vulns) ?? lastModified;

    const total = Number(parsed.totalResults ?? vulns.length);
    if (vulns.length < NVD_PAGE_SIZE || (page + 1) * NVD_PAGE_SIZE >= total) {
      return { records: collected, lastModified, truncated: false, error };
    }
  }

  return { records: collected, lastModified, truncated: true, error };
}

// ---------------------------------------------------------------------------
// OSV batch (the keyless fallback)
// ---------------------------------------------------------------------------

interface OsvQuery {
  version?: string;
  package?: { name: string; ecosystem?: string };
}

/**
 * OSV's batch endpoint: every product in one POST, no key needed.
 *
 * OSV is an open-source database, so it answers well for OSS-packaged programs and poorly for
 * proprietary Windows software (an exact-ecosystem lookup fails on a name OSV does not carry, so
 * the ecosystem is left out and a missing answer is the normal case, not an error).
 */
async function osvBatch(
  http: Http,
  ttlMs: number,
  queries: OsvQuery[],
): Promise<{ results: { id: string }[][]; error?: string }> {
  if (queries.length === 0) return { results: [] };
  const body = JSON.stringify({ queries });
  const res: CachedFetch = await postCached(http.cacheDir, OSV_BATCH, body, ttlMs);
  if (!res.body) return { results: [], error: res.error ?? "osv: feed unreachable" };
  try {
    const parsed = JSON.parse(res.body) as { results?: { vulns?: { id?: string }[] }[] };
    const rows = parsed.results ?? [];
    return {
      results: queries.map((_, i) =>
        (rows[i]?.vulns ?? []).map((v) => ({ id: String(v.id ?? "") })).filter((v) => v.id !== ""),
      ),
    };
  } catch (cause) {
    return { results: [], error: `osv: answer was not valid JSON: ${String(cause)}` };
  }
}

/** The CVE id inside an OSV advisory id (`GHSA-…`, `ALPINE-CVE-…`, `BIT-CVE-…`), when there is one. */
export function osvCveId(advisoryId: string): string | null {
  const m = /(CVE-\d{4}-\d{4,})/i.exec(advisoryId);
  const id = m?.[1];
  return id ? id.toUpperCase() : null;
}

// ---------------------------------------------------------------------------
// The lookup itself
// ---------------------------------------------------------------------------

export interface ProductLookupResult {
  /** Normalised product name -> records, in the shape `matchProgram` reads. */
  byProduct: Map<string, CveRecord[]>;
  /** CVE id -> first record seen, so a KEV-only hit can be enriched without a live call. */
  byCve: Map<string, CveRecord>;
  stats: ProductLookupStats;
}

/**
 * Loads the CVE records for the given product names, keyed NVD when a valid key exists and the
 * OSV-plus-cache fallback otherwise.
 *
 * The per-run budget is what keeps `check_cves` from turning into a 350-request crawl on a cold
 * cache: NVD names are refreshed at most `productsPerRun` per run and the rest are deferred to the
 * next one, which the answer reports instead of hiding. A deferred product is not an error, and a
 * name the cache already knows is answered from disk in every mode.
 */
export async function lookupProducts(options: {
  http: Http;
  config: ConfigStore;
  cacheDir: string;
  /**
   * Every candidate product name the inventory produced, deduplicated by the caller. The
   * (optional) version rides along because OSV rejects a batch query that carries neither a
   * version nor a commit; NVD's keyword search does not need it.
   */
  names: { name: string; wanted: Set<string>; version?: string | null }[];
  ttlMs: number;
  force: boolean;
  /**
   * Normalised names the caller wants asked first — in practice the products with a KEV hit, so a
   * cold keyed start reaches the actively exploited products inside the first call's time budget.
   */
  priority?: Set<string>;
  /**
   * Called for every per-product HTTP failure worth an activity-log line (429 and 404, task 5).
   * Optional because not every caller owns an activity log.
   */
  onStatus?: (product: string, status: number) => void;
}): Promise<ProductLookupResult> {
  const { http, config, cacheDir, names } = options;
  const settings = config.settings;
  const offline = process.env.WSMD_OFFLINE === "1";
  const cache = new ProductCache(cacheDir);
  const keyState = resolveNvdKey(config);
  const keyed = keyState.key !== null;
  const mode: LookupMode = keyed ? "nvd-keyed" : "keyless-osv+cached";

  // One entry per distinct failure reason with a product count, because an offline keyed run
  // fails on every product and must not flood `source_errors` with 60 near-identical lines.
  const errorCounts = new Map<string, number>();
  const noteError = (message: string): void => {
    errorCounts.set(message, (errorCounts.get(message) ?? 0) + 1);
  };
  let refreshed = 0;
  let deferred = 0;
  let failed429 = 0;
  let failed404 = 0;
  let failedOther = 0;
  let notFound = 0;

  // Defensive defaults, so a config written before v0.6.3 (or a minimal test config) still paces.
  const notFoundTtlMs = (settings.nvdNotFoundTtlHours ?? 6) * 60 * 60 * 1000;

  // Keyed mode is the only one that walks NVD per product, so the budget protects it. The keyless
  // path asks OSV in a single batch request no matter how many products it carries, so it can take
  // the whole inventory at once and never defers work to a later run.
  const budget = keyed
    ? Math.max(1, Math.round(settings.nvdProductsPerRun))
    : Math.max(1, names.length);

  const stale = names.filter(({ name }) => !cache.isFresh(name, options.ttlMs, keyed, notFoundTtlMs, options.force));

  if (keyed) {
    // KEV-priority first, then whatever order the inventory produced; the slice below is the
    // count budget, the time budget is checked inside the worker loop.
    const queue = options.priority
      ? [...stale].sort((a, b) => Number(options.priority?.has(b.name)) - Number(options.priority?.has(a.name)))
      : [...stale];
    const due = queue.slice(0, budget);
    deferred = stale.length - due.length;

    const throttle = new NvdThrottle(
      Math.max(100, Math.round((settings.nvdWindowMs ?? 30_000) / Math.max(1, settings.nvdRatePerWindow ?? 50))),
      offline,
    );

    const runOne = async ({ name, wanted }: { name: string; wanted: Set<string> }): Promise<void> => {
      const prev = cache.get(name);
      const since = options.force ? null : (prev?.not_found_at ? null : (prev?.last_modified ?? null));
      const res = await nvdProductQuery(http, {
        name,
        wanted,
        key: keyState.key,
        sinceModified: since,
        maxPages: Math.max(1, Math.round(settings.nvdMaxPages)),
        throttle,
      });
      const status = res.status ?? 0;
      if (status === 429) {
        // The whole queue pauses on this answer; the product keeps no cache entry and is asked
        // again on the next run (a transient failure is not done, task 2).
        throttle.rateLimited(res.retryAfterMs);
        failed429 += 1;
        noteError(res.error ?? "HTTP 429");
        options.onStatus?.(name, 429);
        return;
      }
      if (status === 404) {
        // With a key set, NVD answers 404 flakily (observed live: empty body, `Invalid parameter:
        // apiKey.`), so it counts as transient and is retried next run — caching it as "no CVEs"
        // is what made the 404 totals jump 17→12→3→35 between runs.
        failed404 += 1;
        noteError(res.error ?? "HTTP 404");
        options.onStatus?.(name, 404);
        return;
      }
      if (res.error && res.records.length === 0) {
        failedOther += 1;
        noteError(res.error);
        return;
      }
      throttle.succeeded();
      // Incremental answers only add and update; a full one (no `since`) also drops CVEs the
      // product stopped being mentioned in. A full answer with zero results is a negative marker
      // with the short not-found TTL, not a day-fresh "done".
      const merged = mergeRecords(prev?.records ?? [], res.records, since === null);
      cache.set(name, {
        name,
        records: merged,
        last_modified: res.lastModified ?? prev?.last_modified ?? null,
        fetched_at: new Date().toISOString(),
        source: "nvd",
        truncated: res.truncated,
        not_found_at: merged.length === 0 ? new Date().toISOString() : null,
      });
      if (merged.length === 0) notFound += 1;
      refreshed += 1;
    };

    const startedAt = Date.now();
    const budgetMs = Math.max(1_000, Math.round(settings.nvdCallBudgetMs ?? 20_000));
    const concurrency = Math.max(1, Math.round(settings.nvdConcurrency ?? 1));
    const work = [...due];

    // One call must never block until the last product: the workers stop at the time budget and
    // the rest drains in the background, so the MCP transport sees an answer well before a client
    // timeout while the warm-up keeps going (task 1).
    const worker = async (): Promise<void> => {
      while (work.length > 0 && (offline || Date.now() - startedAt < budgetMs)) {
        const item = work.shift();
        if (item) await runOne(item);
      }
    };
    await Promise.all(Array.from({ length: Math.min(concurrency, work.length) }, () => worker()));

    if (work.length > 0) {
      if (offline) {
        // Offline there is nothing to wait for; the products that did not fit the loop are simply
        // deferred and the tests keep their deterministic counts.
        deferred += work.length;
      } else {
        warmUp(cacheDir, cache, work, runOne);
      }
    }
  } else {
    // Keyless: one OSV batch for everything. OSV rejects a query without a version or commit —
    // and one bad query fails the whole batch — so only products the inventory saw a version for
    // are asked about; the rest stay deferred instead of poisoning the request.
    const osvTargets = stale.filter(({ version }) => Boolean(version)).slice(0, budget);
    const batch = await osvBatch(
      http,
      options.ttlMs,
      osvTargets.map(({ name, version }) => ({ version: String(version), package: { name } })),
    );
    if (batch.error) errorCounts.set(batch.error, (errorCounts.get(batch.error) ?? 0) + 1);
    batch.results.forEach((vulns, i) => {
      const target = osvTargets[i];
      if (!target) return;
      const records: CveRecord[] = [];
      for (const v of vulns) {
        const cve = osvCveId(v.id);
        if (!cve) continue;
        for (const wanted of target.wanted) {
          records.push({
            cve_id: cve,
            product: wanted,
            vendor: null,
            summary: null,
            published: null,
            cvss: null,
            range_from: null,
            range_below: null,
            fixed_version: null,
          });
        }
      }
      if (records.length === 0 && target.wanted.size === 0) return;
      cache.set(target.name, {
        name: target.name,
        records,
        last_modified: null,
        fetched_at: new Date().toISOString(),
        source: "osv",
        truncated: false,
      });
      refreshed += 1;
    });
    deferred = Math.max(0, stale.length - osvTargets.length);
  }

  cache.save();

  const byProduct = new Map<string, CveRecord[]>();
  const byCve = new Map<string, CveRecord>();
  for (const { name } of names) {
    const entry = cache.get(name);
    if (!entry) continue;
    const list = byProduct.get(normName(name)) ?? [];
    for (const rec of entry.records) {
      list.push(rec);
      if (!byCve.has(rec.cve_id)) byCve.set(rec.cve_id, rec);
    }
    byProduct.set(normName(name), list);
  }

  const pending = names.filter(({ name }) => !cache.isFresh(name, options.ttlMs, keyed, notFoundTtlMs, options.force)).length;

  return {
    byProduct,
    byCve,
    stats: {
      mode,
      products_cached: cache.size,
      refreshed,
      deferred,
      fetched_at: cache.newestFetchedAt(),
      errors: [...errorCounts.entries()].map(([message, count]) =>
        count === 1 ? message : `${message} (${String(count)} products)`,
      ),
      products_total: names.length,
      pending,
      failed_429: failed429,
      failed_404: failed404,
      failed_other: failedOther,
      not_found: notFound,
      warm_up_running: warmUpActive(cacheDir),
    },
  };
}

/**
 * The NVD walks that are still draining in the background after their `check_cves` call answered.
 *
 * Keyed by cache directory, so a second call while a warm-up runs sees it is running (and the
 * products it holds are not double-fetched: the drain owns the `due` array alone). One drain per
 * directory at a time; a fresh call's own slice is the intersection-free part.
 */
const warmUps = new Set<string>();

/** Whether a background drain is running for this cache directory. */
export function warmUpActive(cacheDir: string): boolean {
  return warmUps.has(cacheDir);
}

/**
 * Continues a keyed queue after the call answered: processes the products the time budget left
 * (and a later call's slice sees them as fresh once saved), then persists the cache once. Failures
 * inside the drain follow the same rules as inside the call: a transient failure leaves the
 * product without an entry, so a later run asks again.
 */
function warmUp(
  cacheDir: string,
  cache: ProductCache,
  work: { name: string; wanted: Set<string> }[],
  runOne: (item: { name: string; wanted: Set<string> }) => Promise<void>,
): void {
  warmUps.add(cacheDir);
  void (async () => {
    try {
      while (work.length > 0) {
        const item = work.shift();
        if (item) await runOne(item);
      }
    } finally {
      warmUps.delete(cacheDir);
      cache.save();
    }
  })();
}

/**
 * Folds a fresh answer into the cached records of one product.
 *
 * NVD's incremental query only returns what changed, so a fresh record replaces the stored one of
 * the same CVE id and unseen ids are added. A full answer (no `sinceModified`) replaces the whole
 * list, because a product that stopped being mentioned should stop producing hits.
 */
export function mergeRecords(prev: CveRecord[], fresh: CveRecord[], full: boolean): CveRecord[] {
  if (fresh.length === 0) return prev;
  if (full) {
    const byId = new Map<string, CveRecord>();
    for (const r of fresh) if (!byId.has(r.cve_id)) byId.set(r.cve_id, r);
    return [...byId.values()];
  }
  const byId = new Map<string, CveRecord>();
  for (const r of prev) if (!byId.has(r.cve_id)) byId.set(r.cve_id, r);
  for (const r of fresh) byId.set(r.cve_id, r);
  return [...byId.values()];
}
