import { existsSync, mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { join } from "node:path";

import { unzip } from "../../utils/zip.js";
import { normName, severityBand } from "../../utils/matching.js";
import type { CachedFetch, Http } from "../../utils/net.js";
import type { CveHit, MatchConfidence } from "../../model.js";

const KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json";
const NVD_API = "https://services.nvd.nist.gov/rest/json/cves/2.0";
const EPSS_API = "https://api.first.org/data/v1/epss";
const GITHUB_RELEASES = "https://api.github.com/repos/CVEProject/cvelistV5/releases?per_page=1";

/**
 * Rough size of the whole cvelistV5 corpus, used only to report how much of it the accumulated local
 * delta index already covers. It is an estimate, not an API number, so `check_cves` labels the field
 * `index_coverage` and the reader can tell "no hits found" from "index still thin".
 */
export const CVELIST_FULL_CORPUS_ESTIMATE = 290_000;

/**
 * Product-name aliases for the gap between a Windows display name and a CVE product name.
 *
 * Phase 0 measured that an exact KEV name match hits 0.5 % of a real inventory, almost entirely
 * because of this gap ("Google Chrome" vs "Chrome"). A small explicit table is more honest than a
 * fuzzy match that quietly invents identities, and it is extendable in the config.
 */
const ALIASES: Record<string, string[]> = {
  "google chrome": ["chrome", "chromium"],
  chrome: ["google chrome"],
  "mozilla firefox": ["firefox"],
  firefox: ["mozilla firefox"],
  "vlc media player": ["vlc"],
  vlc: ["vlc media player"],
  "microsoft edge": ["edge", "microsoft edge"],
  edge: ["microsoft edge"],
  "7 zip": ["7 zip", "7zip", "7-zip"],
  "notepad": ["notepad", "notepad "],
  "microsoft visual studio code": ["visual studio code", "vs code", "visual studio code insid"],
  "opera browser": ["opera"],
  "waterfox browser": ["waterfox"],
  "tailscale": ["tailscale"],
  zoom: ["zoom workplace", "zoom"],
  "winrar": ["winrar"],
  "git for windows": ["git", "git for windows"],
  "obsidian": ["obsidian"],
  "mozilla thunderbird": ["thunderbird"],
};

export interface KevEntry {
  cve_id: string;
  product: string;
  vendor: string | null;
  due_date: string | null;
  name: string | null;
}

export interface KevIndex {
  /** Normalised product name -> CVE ids. */
  byProduct: Map<string, KevEntry[]>;
  byCve: Map<string, KevEntry>;
  total: number;
  fetched_at: string | null;
  from: CachedFetch["from"];
  error?: string;
}

export interface CveRecord {
  cve_id: string;
  product: string;
  vendor: string | null;
  summary: string | null;
  published: string | null;
  cvss: number | null;
  /** Affected version range, kept as the raw strings the source used. */
  range_from: string | null;
  range_below: string | null;
  /** Versions listed as unaffected that are above the affected range: the fix version. */
  fixed_version: string | null;
}

export interface ProductIndex {
  /** Normalised product name -> CVE records. */
  byProduct: Map<string, CveRecord[]>;
  /**
   * CVE id -> one of its records. A CVE is one document, so cvss/summary/published are the same for
   * every record of that id; the map exists so a KEV-only hit can be enriched without a live NVD call.
   */
  byCve: Map<string, CveRecord>;
  totalCves: number;
  products: number;
  fetched_at: string | null;
  from: CachedFetch["from"];
  error?: string;
}

/**
 * Loads CISA KEV, cached on disk with a TTL.
 *
 * Phase 0: the feed answers in 0.2 s at 1.8 MB, but it is fetched at most daily; an offline run
 * simply reports `from: "none"` and the caller degrades to `cve_status: "unknown"`.
 */
export async function loadKev(http: Http, ttlMs: number): Promise<KevIndex> {
  const empty: KevIndex = { byProduct: new Map(), byCve: new Map(), total: 0, fetched_at: null, from: "none" };
  const res = await http.get(KEV_URL, ttlMs);
  if (!res.body) return { ...empty, from: "none", error: res.error };

  let parsed: { vulnerabilities?: unknown };
  try {
    parsed = JSON.parse(res.body) as { vulnerabilities?: unknown };
  } catch (cause) {
    return { ...empty, from: "none", error: `KEV feed is not valid JSON: ${String(cause)}` };
  }

  const rows = Array.isArray(parsed.vulnerabilities) ? (parsed.vulnerabilities as Record<string, unknown>[]) : [];
  const byProduct = new Map<string, KevEntry[]>();
  const byCve = new Map<string, KevEntry>();

  for (const row of rows) {
    const cveId = String(row.cveID ?? "").trim();
    if (cveId === "") continue;
    const entry: KevEntry = {
      cve_id: cveId,
      product: String(row.product ?? "").trim(),
      vendor: String(row.vendorProject ?? "").trim() || null,
      due_date: String(row.dueDate ?? "").trim() || null,
      name: String(row.vulnerabilityName ?? "").trim() || null,
    };
    byCve.set(cveId, entry);
    const key = normName(entry.product);
    if (key === "") continue;
    const list = byProduct.get(key);
    if (list) list.push(entry);
    else byProduct.set(key, [entry]);
  }

  return { byProduct, byCve, total: byCve.size, fetched_at: res.fetched_at, from: res.from, error: res.error };
}

/** Every CVE id KEV carries for a product name, including the alias table. */
export function kevForProduct(kev: KevIndex, productName: string): KevEntry[] {
  const keys = new Set([normName(productName), ...(ALIASES[normName(productName)] ?? []).map(normName)]);
  const out = new Map<string, KevEntry>();
  for (const k of keys) {
    for (const e of kev.byProduct.get(k) ?? []) out.set(e.cve_id, e);
  }
  return [...out.values()];
}

/**
 * Loads the cvelistV5 bulk index, building it on first use.
 *
 * The full dataset is 602 MB, which no one wants on a first run, so this takes the hourly delta
 * (about 5 MB) and *accumulates* it into a local index file: every run that finds a newer delta
 * merges it in, so coverage grows over the days without ever downloading the whole corpus. What the
 * index currently covers is reported, never guessed.
 */
export async function loadProductIndex(
  http: Http,
  ttlMs: number,
  cacheDir: string,
): Promise<ProductIndex> {
  const indexPath = join(cacheDir, "cvelist-index.json");
  const index = readIndex(indexPath);
  const res = await http.get(GITHUB_RELEASES, ttlMs);

  const fail = (error: string): ProductIndex => ({
    byProduct: index.byProduct,
    byCve: index.byCve,
    totalCves: index.totalCves,
    products: index.byProduct.size,
    fetched_at: index.fetched_at,
    from: res.body ? res.from : "none",
    error,
  });

  if (!res.body) return fail(res.error ?? "no network and no cached delta");

  let release: { tag_name?: string; assets?: { name?: string; browser_download_url?: string }[] } | undefined;
  try {
    const parsed = JSON.parse(res.body);
    release = Array.isArray(parsed) ? parsed[0] : undefined;
  } catch (cause) {
    return fail(`GitHub releases answer was not valid JSON: ${String(cause)}`);
  }
  if (!release?.tag_name) return fail("GitHub releases answer carried no tag");

  if (release.tag_name === index.tag) {
    return { ...fail(""), fetched_at: index.fetched_at, from: "cache" };
  }

  const asset = (release.assets ?? []).find((a) => String(a.name ?? "").includes("delta"));
  const url = asset?.browser_download_url;
  if (!url) return fail("the release carried no delta asset");

  const zipRes = await http.getBinary(url, ttlMs * 40);
  if (!zipRes.body) return fail(`delta download failed: ${zipRes.error ?? "no body"}`);

  let merged: { cves: number };
  try {
    merged = mergeDelta(index, zipRes.body);
  } catch (cause) {
    return fail(`delta unzip failed: ${String(cause)}`);
  }

  index.tag = release.tag_name;
  index.fetched_at = new Date().toISOString();
  writeIndex(indexPath, index);

  return {
    byProduct: index.byProduct,
    byCve: index.byCve,
    totalCves: index.totalCves,
    products: index.byProduct.size,
    fetched_at: index.fetched_at,
    from: "network",
    error: merged.cves === 0 ? "the delta contained no parsable CVE records" : undefined,
  };
}

interface MutableIndex {
  tag: string | null;
  fetched_at: string | null;
  byProduct: Map<string, CveRecord[]>;
  /** CVE id -> first record seen for it, so a KEV-only hit can be enriched from the local index. */
  byCve: Map<string, CveRecord>;
  totalCves: number;
}

function readIndex(path: string): MutableIndex {
  try {
    const raw = JSON.parse(readFileSync(path, "utf8")) as {
      tag?: string | null;
      fetched_at?: string | null;
      records?: CveRecord[];
    };
    const byProduct = new Map<string, CveRecord[]>();
    const byCve = new Map<string, CveRecord>();
    for (const rec of raw.records ?? []) {
      const key = normName(rec.product);
      if (key === "" || !rec.cve_id) continue;
      const list = byProduct.get(key);
      if (list) list.push(rec);
      else byProduct.set(key, [rec]);
      if (!byCve.has(rec.cve_id)) byCve.set(rec.cve_id, rec);
    }
    return { tag: raw.tag ?? null, fetched_at: raw.fetched_at ?? null, byProduct, byCve, totalCves: byCve.size };
  } catch {
    return { tag: null, fetched_at: null, byProduct: new Map(), byCve: new Map(), totalCves: 0 };
  }
}

function writeIndex(path: string, index: MutableIndex): void {
  try {
    mkdirSync(join(path, ".."), { recursive: true });
    const records = [...index.byProduct.values()].flat();
    writeFileSync(path, JSON.stringify({ tag: index.tag, fetched_at: index.fetched_at, records }), "utf8");
  } catch {
    // An index that cannot be persisted is rebuilt on the next run; nothing is lost but time.
  }
}

/** cvelistV5 JSON in the CVE 5.0 schema, as far as this server reads it. */
interface CveV5 {
  cveMetadata?: { cveId?: string; datePublished?: string };
  containers?: {
    cna?: CveContainer;
    adp?: (CveContainer & { providerMetadata?: { shortName?: string } })[];
  };
}

interface CveContainer {
  title?: string;
  descriptions?: { value?: string; lang?: string }[];
  metrics?: { cvssV3_1?: { baseScore?: number }; cvssV4_0_0?: { baseScore?: number }; cvssV3_0?: { baseScore?: number } }[];
  affected?: {
    product?: string;
    vendor?: string;
    versions?: { version?: string; status?: string; lessThan?: string; versionType?: string }[];
    defaultStatus?: string;
  }[];
}

/** Unzips one delta and folds its records into the index. */
function mergeDelta(index: MutableIndex, buf: Buffer): { cves: number } {
  let count = 0;

  for (const entry of unzip(buf)) {
    if (!entry.name.endsWith(".json")) continue;
    let doc: CveV5;
    try {
      doc = JSON.parse(entry.data.toString("utf8")) as CveV5;
    } catch {
      continue;
    }
    const id = doc.cveMetadata?.cveId;
    if (!id) continue;

    const records = extractRecords(doc);
    if (records.length === 0) continue;

    for (const rec of records) {
      const key = normName(rec.product);
      if (key === "") continue;
      const list = index.byProduct.get(key);
      if (list) {
        const existing = list.find((r) => r.cve_id === rec.cve_id);
        if (existing) Object.assign(existing, rec);
        else list.push(rec);
      } else {
        index.byProduct.set(key, [rec]);
      }
    }
    const first = records[0];
    if (first && !index.byCve.has(id)) {
      index.byCve.set(id, first);
      index.totalCves += 1;
    }
    count += 1;
  }
  return { cves: count };
}

/**
 * One record per (CVE, product) pair the document mentions.
 *
 * The ADP container of NVD is preferred for CVSS because the CNA often publishes no score at all;
 * a score found anywhere in the document is used rather than dropping the CVE for lack of one.
 */
function extractRecords(doc: CveV5): CveRecord[] {
  const id = doc.cveMetadata?.cveId ?? "";
  const published = doc.cveMetadata?.datePublished ?? null;

  const containers: CveContainer[] = [];
  if (doc.containers?.cna) containers.push(doc.containers.cna);
  for (const adp of doc.containers?.adp ?? []) containers.push(adp);

  let cvss: number | null = null;
  let summary: string | null = null;
  const products = new Map<string, { vendor: string | null; from: string | null; below: string | null; fixed: string | null }>();

  for (const c of containers) {
    for (const m of c.metrics ?? []) {
      const score = m.cvssV4_0_0?.baseScore ?? m.cvssV3_1?.baseScore ?? m.cvssV3_0?.baseScore;
      if (typeof score === "number" && cvss === null) cvss = score;
    }
    if (summary === null) {
      const d = (c.descriptions ?? []).find((x) => String(x.lang ?? "en").startsWith("en")) ?? c.descriptions?.[0];
      if (d?.value) summary = d.value.split("\n")[0]?.slice(0, 400) ?? null;
    }
    for (const aff of c.affected ?? []) {
      const product = String(aff.product ?? "").trim();
      if (product === "") continue;
      let from: string | null = null;
      let below: string | null = null;
      let fixed: string | null = null;
      for (const v of aff.versions ?? []) {
        const status = String(v.status ?? "");
        if (status === "affected") {
          if (v.version && v.version !== "0") from = from ?? v.version;
          if (v.lessThan) below = v.lessThan;
        } else if (status === "unaffected") {
          fixed = pickFixed(fixed, v.version ?? null, below);
        }
      }
      if (fixed === null && below !== null) fixed = below;
      const prev = products.get(product.toLowerCase());
      products.set(product.toLowerCase(), {
        vendor: String(aff.vendor ?? "").trim() || prev?.vendor || null,
        from: from ?? prev?.from ?? null,
        below: below ?? prev?.below ?? null,
        fixed: fixed ?? prev?.fixed ?? null,
      });
    }
  }

  return [...products.entries()].map(([product, r]) => ({
    cve_id: id,
    product,
    vendor: r.vendor,
    summary,
    published,
    cvss,
    range_from: r.from,
    range_below: r.below,
    fixed_version: r.fixed,
  }));
}

function pickFixed(current: string | null, candidate: string | null, below: string | null): string | null {
  if (candidate === null || candidate === "" || candidate === "unspecified") return current;
  if (current === null) return candidate;
  void below;
  return candidate;
}

/**
 * Fetches EPSS scores in batches of 100 (the API's own limit), all served from the disk cache.
 *
 * Returns a map of CVE id -> probability. A CVE the API does not know simply is absent, which the
 * caller renders as a null score rather than an error.
 */
export async function fetchEpss(http: Http, ttlMs: number, cveIds: string[]): Promise<Map<string, number>> {
  const out = new Map<string, number>();
  const unique = [...new Set(cveIds)].filter((id) => /^CVE-\d{4}-\d+$/i.test(id));
  if (unique.length === 0) return out;

  const cacheOnly = process.env.WSMD_OFFLINE === "1";
  void cacheOnly;

  for (let i = 0; i < unique.length; i += 100) {
    const batch = unique.slice(i, i + 100);
    const url = `${EPSS_API}?cve=${batch.join(",")}`;
    const res = await http.get(url, ttlMs);
    if (!res.body) continue;
    try {
      const j = JSON.parse(res.body) as { data?: { cve?: string; epss?: string }[] };
      for (const row of j.data ?? []) {
        if (!row?.cve) continue;
        const value = Number(row.epss);
        if (Number.isFinite(value)) out.set(row.cve, value);
      }
    } catch {
      // A malformed EPSS answer costs the score, not the run.
    }
  }
  return out;
}

/**
 * Single-CVE detail from NVD API 2.0.
 *
 * Phase 0 measured 4 requests per 30 s without an API key, so this is deliberately the *only*
 * place the server calls NVD live, and one call per user request at that.
 */
export async function nvdCveDetail(
  http: Http,
  timeoutOnlyMs: number,
  cveId: string,
): Promise<{ data: unknown | null; error?: string; from: CachedFetch["from"] }> {
  void timeoutOnlyMs;
  const url = `${NVD_API}?cveId=${encodeURIComponent(cveId)}`;
  const res = await http.get(url, 24 * 60 * 60 * 1000);
  if (!res.body) return { data: null, error: res.error ?? "NVD unreachable", from: "none" };
  try {
    return { data: JSON.parse(res.body), from: res.from };
  } catch (cause) {
    return { data: null, error: `NVD answer was not valid JSON: ${String(cause)}`, from: res.from };
  }
}

export function band(score: number | null): ReturnType<typeof severityBand> {
  return severityBand(score);
}

/** Confidence ordering, so the weakest link across a set of hits can be picked. */
const CONFIDENCE_ORDER: MatchConfidence[] = ["low", "medium", "high", "exact"];

export function weakestConfidence(hits: CveHit[]): MatchConfidence {
  if (hits.length === 0) return "medium";
  let worst = CONFIDENCE_ORDER.length - 1;
  for (const h of hits) worst = Math.min(worst, CONFIDENCE_ORDER.indexOf(h.match_confidence));
  return CONFIDENCE_ORDER[worst] ?? "medium";
}

export function existsFileSync(path: string): boolean {
  return existsSync(path);
}
