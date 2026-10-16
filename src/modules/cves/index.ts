import { z } from "zod";

import type { ToolDefinition, ToolContext } from "../../types.js";
import { fail, ok } from "../../utils/result.js";
import {
  CVELIST_FULL_CORPUS_ESTIMATE,
  fetchEpss,
  kevForProduct,
  loadKev,
  loadProductIndex,
  nvdCveDetail,
  type CveRecord,
  type ProductIndex,
} from "../cves/feeds.js";
import { candidates, matchProgram, severityOf } from "../cves/engine.js";
import { drainActive, lookupProducts, resolveNvdKey, startIdleDrain } from "./products.js";
import { normName, productFamily } from "../../utils/matching.js";
import type { CveHit, InventoryEntry } from "../../model.js";
import { groupMatchesIntoTodos, mergeTodo } from "../todos/todo.js";

/** Extracts the english description and the highest CVSS out of an NVD API 2.0 answer. */
function nvdFields(cve: Record<string, unknown>): { cvss: number | null; description: string | null } {
  const metrics = (cve.metrics ?? {}) as Record<string, { cvssData?: { baseScore?: number } }[]>;
  const scoreOf = (key: string): number | undefined => {
    const score = metrics[key]?.[0]?.cvssData?.baseScore;
    return typeof score === "number" ? score : undefined;
  };
  const descriptions = (cve.descriptions ?? []) as { value?: string; lang?: string }[];
  // NVD mixes translated ADP descriptions into the list, so the english entry is preferred and only
  // the first one is kept.
  const english = descriptions.find((d) => String(d.lang ?? "").toLowerCase().startsWith("en"));
  return {
    cvss: scoreOf("cvssMetricV40") ?? scoreOf("cvssMetricV31") ?? null,
    description: String((english ?? descriptions[0])?.value ?? "").replace(/\s+/g, " ").trim(),
  };
}

/** How many unscored CVEs one `check_cves` run may look up at NVD (keyless rate limit is 4 / 30 s). */
const NVD_ENRICH_CAP = 20;

/**
 * Every product name the inventory stands for, deduplicated, as the lookup wants it.
 *
 * The same candidate list the engine matches with drives the queries, so a name that could
 * produce a hit is a name that was asked about. Each entry's `wanted` set names exactly its own
 * normalised form: the engine's per-candidate lookup then finds this product's answer and nothing
 * else, which is what keeps one cache entry per installed program instead of a corpus copy.
 */
export function productNames(inventory: InventoryEntry[]): { name: string; wanted: Set<string>; version: string | null }[] {
  const wanted = new Map<string, { set: Set<string>; version: string | null }>();
  for (const entry of inventory) {
    if (entry.installer_artifact === true) continue;
    for (const cand of candidates(entry)) {
      const key = normName(cand.name);
      if (key === "") continue;
      const known = wanted.get(key) ?? { set: new Set<string>(), version: null };
      known.set.add(key);
      // OSV rejects a batch query with neither a version nor a commit, so the installed version
      // rides along with the name. NVD's keyword search simply ignores it.
      if (known.version === null && entry.version) known.version = entry.version;
      wanted.set(key, known);
    }
  }
  return [...wanted.entries()].map(([name, { set, version }]) => ({ name, wanted: set, version }));
}

/**
 * Fills the missing CVSS of KEV hits from the cached NVD answer.
 *
 * The local cvelist index is already consulted by the engine; whatever is still unscored is looked
 * up through the disk-cached NVD helper (24 h TTL, so a warm store costs no call at all). Each CVE
 * is fetched at most once per run and the answer is applied to **every** hit object that carries the
 * id: the same CVE appears in several programs' hit lists, and enriching only the first object left
 * the live beta with `cvss: 8.8` on one Edge to-do and `cvss: null` on the other. A hit that stays
 * unscored is marked `cvss_source: "nvd_unreachable"` rather than reported as `severity: "none"`.
 */
export async function enrichKevHits(ctx: ToolContext, hits: CveHit[]): Promise<number> {
  // One entry per CVE id, holding every hit object that carries it and still needs a score.
  const missing = new Map<string, CveHit[]>();
  for (const hit of hits) {
    if (!hit.kev || hit.cvss !== null || hit.cvss_source !== undefined) continue;
    const list = missing.get(hit.cve_id);
    if (list) list.push(hit);
    else missing.set(hit.cve_id, [hit]);
  }

  let enriched = 0;
  let failures = 0;
  for (const [cveId, targets] of missing) {
    // Two dead lookups in a row mean NVD is unreachable or throttling; the rest stay unenriched
    // instead of burning the rate limit on the same answer.
    if (failures >= 2 || enriched >= NVD_ENRICH_CAP) {
      for (const hit of targets) hit.cvss_source = "nvd_unreachable";
      continue;
    }
    const res = await nvdCveDetail(ctx.http, ctx.config.settings.httpTimeoutMs, cveId, resolveNvdKey(ctx.config).key);
    const first = res.data
      ? ((res.data as { vulnerabilities?: { cve?: Record<string, unknown> }[] }).vulnerabilities ?? [])[0]
      : undefined;
    const fields = first?.cve ? nvdFields(first.cve) : null;

    if (!res.data || !fields) {
      failures += 1;
      for (const hit of targets) hit.cvss_source = "nvd_unreachable";
      continue;
    }
    failures = 0;
    for (const hit of targets) {
      if (fields.cvss !== null) {
        hit.cvss = fields.cvss;
        hit.severity = severityOf(fields.cvss);
        hit.cvss_source = "nvd";
      } else {
        hit.cvss_source = res.from === "none" ? "nvd_unreachable" : "nvd_no_score";
      }
      if (hit.summary === null && fields.description) hit.summary = fields.description.slice(0, 300);
      if (hit.published === null) hit.published = (first?.cve?.published as string | undefined) ?? null;
    }
    if (fields.cvss !== null) enriched += 1;
  }

  // Whatever the loop capped or skipped still gets an honest marker, so no hit reads as scored.
  for (const hit of hits) {
    if (hit.kev && hit.cvss === null && hit.cvss_source === undefined) hit.cvss_source = "nvd_unreachable";
  }
  return enriched;
}

/**
 * Folds the cvelist delta index into the per-product answers, deduplicated by CVE id (task 3).
 *
 * The per-product records win on collision — an NVD answer carries CVSS, ranges and summaries the
 * delta index may lack — and the index only adds ids the product answers missed. Both directions
 * of `byCve` follow the same rule so a KEV-only enrichment lookup sees the enriched record first.
 */
export function mergeProductIndexes(primary: ProductIndex, fallback: ProductIndex): ProductIndex {
  const byProduct = new Map<string, CveRecord[]>();
  const byCve = new Map<string, CveRecord>(primary.byCve);
  let totalRecords = 0;

  for (const [name, recs] of primary.byProduct) {
    byProduct.set(name, recs);
    totalRecords += recs.length;
  }
  for (const [name, recs] of fallback.byProduct) {
    const known = byProduct.get(name);
    if (!known || known.length === 0) {
      byProduct.set(name, recs);
      totalRecords += recs.length;
      for (const r of recs) if (!byCve.has(r.cve_id)) byCve.set(r.cve_id, r);
      continue;
    }
    const seen = new Set(known.map((r) => r.cve_id));
    let added = 0;
    for (const r of recs) {
      if (seen.has(r.cve_id)) continue;
      seen.add(r.cve_id);
      known.push(r);
      added += 1;
      if (!byCve.has(r.cve_id)) byCve.set(r.cve_id, r);
    }
    totalRecords += added;
  }

  return {
    byProduct,
    byCve,
    totalCves: byCve.size,
    products: byProduct.size,
    fetched_at: primary.fetched_at ?? fallback.fetched_at,
    from: primary.from !== "none" ? primary.from : fallback.from,
    error: [primary.error, fallback.error].filter((e): e is string => Boolean(e)).join("; ") || undefined,
  };
}

/**
 * The machine-readable completeness verdict of a `check_cves` run (task 4).
 *
 * It answers the question the hit count cannot: "is few hits here because the machine is patched
 * or because the data source was not fully reached yet?" A pending product list, a rate-limited
 * lookup, or a background warm-up still running all make the answer `incomplete`, and the hint
 * tells an agent to wait and re-run rather than conclude.
 */
export function buildCompleteness(
  stats: import("./products.js").ProductLookupStats,
  warmUpRunning: boolean,
  cveStatus: "checked" | "unknown",
): {
  status: "complete" | "incomplete";
  warming_up: boolean;
  reasons: string[];
  lookups: {
    total: number;
    cached: number;
    deferred: number;
    failed_429: number;
    failed_404: number;
    failed_other: number;
    not_found: number;
  };
  hint: string;
} {
  const reasons: string[] = [];
  if (cveStatus === "unknown") reasons.push("no CVE source reachable at all");
  if (stats.pending > 0) reasons.push(`${String(stats.pending)} of ${String(stats.products_total)} product lookups unanswered`);
  if (stats.deferred > 0) reasons.push(`${String(stats.deferred)} product(s) beyond the per-run budget`);
  if (stats.failed_429 > 0) reasons.push(`${String(stats.failed_429)} product(s) rate limited (HTTP 429)`);
  if (stats.failed_404 > 0) reasons.push(`${String(stats.failed_404)} product(s) answered 404 (NVD flakes on this with a key)`);
  if (stats.failed_other > 0) reasons.push(`${String(stats.failed_other)} product(s) failed transiently`);
  if (warmUpRunning) reasons.push("NVD warm-up continues in the background");

  const incomplete = cveStatus === "unknown" || stats.pending > 0 || stats.deferred > 0 || warmUpRunning;
  return {
    status: incomplete ? "incomplete" : "complete",
    warming_up: warmUpRunning || stats.pending > 0 || stats.deferred > 0,
    reasons,
    lookups: {
      total: stats.products_total,
      cached: stats.products_total - stats.pending,
      deferred: stats.deferred,
      failed_429: stats.failed_429,
      failed_404: stats.failed_404,
      failed_other: stats.failed_other,
      not_found: stats.not_found,
    },
    hint: incomplete
      ? "Results incomplete — the NVD data was not fully reached (cold cache and/or rate limits). This is NOT \"patched\": re-run check_cves after a few minutes and compare before drawing a conclusion."
      : "All products were answered from NVD or a fresh cache.",
  };
}

export const cveTools: ToolDefinition[] = [
  {
    name: "check_cves",
    module: "cves",
    title: "Check CVEs",
    description:
      "Match the stored inventory against the CVE sources (per-product NVD lookup, CISA KEV, EPSS) and fill the ToDo list. Answers come from the per-product cache when it is fresh; the network is only touched for what changed. A cold keyed start is paced by NVD's rate limit: the call answers within a time budget and the rest of the queue drains in the background — read `completeness` before concluding.\n" +
      "Never requires the network, but a cold keyed start does need time: see completeness.status \"incomplete\".",
    docs:
      "Offline rule: the run never depends on the network. Every source is read from its disk cache when the cache is " +
      "fresh; when the network is down the expired cache is still used, and only a cold cache with no network yields " +
      "cve_status: \"unknown\" with the inventory left untouched by the CVE layer.\n" +
      "Since v0.6.0 the inventory drives the lookup: each installed product is queried at NVD API 2.0 and its answer is " +
      "cached per product, so coverage is complete on day one instead of growing with the corpus. The answer reports the " +
      "mode and the cache stats. With a valid NVD key the mode is nvd-keyed: since v0.6.3 the requests are paced to " +
      "NVD's window (50 per 30 s by default, settings nvdRatePerWindow / nvdWindowMs) instead of fired as a salvo, an " +
      "HTTP 429 pauses the whole queue for its Retry-After (Cloudflare's bursts answer 429 'error code: 1015' with " +
      "Retry-After: 0, so an exponential backoff with jitter decides the wait), and the call stops at the per-call " +
      "time budget (nvdCallBudgetMs, default 20 s) while a server-side idle-drain timer keeps fetching between calls " +
      "— products with a KEV hit are asked first. Without a key the server falls back to keyless-osv+cached — one OSV batch query plus whatever the " +
      "product cache already holds — which is thinner, and the answer says so rather than letting a small hit count " +
      "look like a clean machine.\n" +
      "Since v0.6.3 a failed lookup is not done, and since v0.6.5 the queue that decides what is done is persistent: " +
      "each product carries its state (pending/done/not_found/failed_transient) with attempt count and time, every " +
      "call continues at the queue's current position, and a product that failed waits at the BACK (round-robin), so " +
      "runs no longer restart at the same names while hundreds never come to word. An idle-drain server timer keeps " +
      "working the queue between calls; deferred is the queue's open remainder and falls towards 0 across runs. " +
      "A 404 whose body is an NVD envelope is a real zero-match answer (not_found, trusted for nvdNotFoundTtlHours, " +
      "counted apart from failures); a 404 with an empty or foreign body is key/Cloudflare flakiness and transient. " +
      "A keyless OSV cache entry never counts fresh in keyed mode — it lacks CVSS and ranges, so keyed mode re-asks " +
      "NVD to enrich it.\n" +
      "The pre-v0.6.0 cvelist delta index is loaded in every mode since v0.6.3 and merged into the product answers " +
      "(deduplicated by CVE id), so a keyed cold start never answers less than a keyless one; its counters are still " +
      "marked deprecated.\n" +
      "EPSS is looked up for every matched CVE — unconfirmed name matches included — and an unreachable feed appears in " +
      "source_errors as an epss entry, so a null score is never silent.\n" +
      "Matching is name-based and carries a confidence per hit; an unsure match is reported with match_confidence and " +
      "never counted as a certain hit.\n" +
      "Before a name match becomes a hit the version verdict decides: a known affected range that excludes the " +
      "installed version drops it, an era-implausible pair (a 2016 CVE against Edge 155) drops too, and an unverifiable " +
      "range keeps it unconfirmed. Rejections count up as dropped_by_verdict; programs only an installer .exe reported " +
      "are skipped. Several installed versions of one product share one to-do whose versions list names the members.",
    input: z.object({
      refresh: z.boolean().optional().describe("Force re-download of the sources even when the cache is fresh"),
      with_epss: z.boolean().optional().describe("Look up EPSS scores for the matched CVEs. Defaults to true"),
    }),
    handler: async (args, ctx) => {
      const store = ctx.store.load();
      if (store.inventory.length === 0) {
        return fail("The inventory is empty — run scan_inventory first");
      }

      const settings = ctx.config.settings;
      const ttl = (h: number) => (args.refresh === true ? 0 : h * 60 * 60 * 1000);
      const cacheDir = `${settings.dataDir}/cache`;

      // KEV first, because its product set decides which NVD lookups the keyed queue asks about
      // first: the actively exploited programs must be answered inside the first call's time budget.
      const kev = await loadKev(ctx.http, ttl(settings.kevTtlHours));
      const priority = new Set<string>();
      for (const entry of store.inventory) {
        if (kevForProduct(kev, entry.name).length === 0) continue;
        for (const cand of candidates(entry)) priority.add(normName(cand.name));
      }

      const [lookup, fallback] = await Promise.all([
        lookupProducts({
          http: ctx.http,
          config: ctx.config,
          cacheDir,
          names: productNames(store.inventory),
          ttlMs: ttl(settings.cvelistTtlHours),
          force: args.refresh === true,
          priority,
          // Per-product 429/404 into the activity log while the call still runs (task 5): a total
          // count alone left operators guessing which product NVD refused.
          onStatus: (product, status) =>
            ctx.activity?.add({
              at: new Date().toISOString(),
              tool: "check_cves",
              ok: false,
              duration_ms: 0,
              origin: "nvd",
              summary: `${product}: HTTP ${String(status)}${status === 429 ? " (rate limited, queue paused)" : ""}`,
            }),
        }),
        // Since v0.6.3 the cvelist delta index loads in every mode (task 3): the keyed cold start
        // that skipped it lost the hits its own NVD keyword queries missed, and the v0.6.2 keyless
        // runs proved the index is a real contributor. The merge below dedupes by CVE id.
        loadProductIndex(ctx.http, ttl(settings.cvelistTtlHours), cacheDir),
      ]);

      // Since v0.6.5 the queue outlives the call: (re-)arm the server-side idle drain with a
      // binding that re-reads the store per tick, so a scan feeds the queue and a key saved or
      // removed between calls takes effect without a restart.
      startIdleDrain({
        http: ctx.http,
        config: ctx.config,
        cacheDir,
        names: () => productNames(ctx.store.load().inventory),
        ttlMs: settings.cvelistTtlHours * 60 * 60 * 1000,
        onStatus: (product, status) =>
          ctx.activity?.add({
            at: new Date().toISOString(),
            tool: "check_cves",
            ok: false,
            duration_ms: 0,
            origin: "nvd",
            summary: `${product}: HTTP ${String(status)} (idle drain)`,
          }),
      });

      // The product cache is the primary source; the delta index adds whatever it carries that the
      // per-product answers do not. Primary records win on id collisions — the NVD answer is the
      // enriched one — and the fallback only contributes ids the primary missed.
      const index = mergeProductIndexes(
        {
          byProduct: lookup.byProduct,
          byCve: lookup.byCve,
          totalCves: lookup.byCve.size,
          products: lookup.byProduct.size,
          fetched_at: lookup.stats.fetched_at,
          from: lookup.stats.refreshed > 0 ? "network" : lookup.stats.products_cached > 0 ? "cache" : "none",
        },
        fallback,
      );


      const dataAvailable = index.byProduct.size > 0 || kev.byCve.size > 0;
      const cveStatus: "checked" | "unknown" = dataAvailable ? "checked" : "unknown";

      const openTodos = store.todos.filter((t) => t.status !== "dismissed");
      const newTodos: import("../../model.js").Todo[] = [];
      let unconfirmedTotal = 0;
      let programsChecked = 0;
      let hitsTotal = 0;
      let kevHits = 0;
      let nvdEnriched = 0;
      /** Name matches the version verdict rejected before they could become a hit (range or era). */
      let droppedByVerdict = 0;
      let skippedInstallerArtifacts = 0;
      /** Set when the EPSS feed answered nothing reachable, so a null score is explained. */
      let epssError: string | undefined;

      if (dataAvailable) {
        const matched: { entry: import("../../model.js").InventoryEntry; hits: import("../../model.js").CveHit[] }[] = [];
        for (const entry of store.inventory) {
          // A program only a downloaded installer .exe reported is archive residue, not installed
          // software, and never becomes a security to-do.
          if (entry.installer_artifact === true) {
            skippedInstallerArtifacts += 1;
            continue;
          }
          const m = matchProgram(entry, index, kev);
          droppedByVerdict += m.dropped;
          if (m.hits.length === 0) continue;
          matched.push({ entry, hits: m.hits });
        }

        // A KEV hit the local index carries no score for is completed from the cached NVD helper
        // before any todo is built, so the hit level and the todo level can never disagree.
        nvdEnriched = await enrichKevHits(ctx, matched.flatMap((m) => m.hits));

        // Several installed versions of one product family (Edge 152 + Edge 155) become ONE todo
        // whose `versions` list carries the members, so the list has no near-duplicate rows.
        for (const todo of groupMatchesIntoTodos(
          matched.map((m) => ({ family: productFamily(m.entry.name), entry: m.entry, hits: m.hits, cveStatus })),
        )) {
          programsChecked += todo.versions?.length ?? 1;
          hitsTotal += todo.cves.length;
          kevHits += todo.cves.filter((h) => h.kev).length;
          unconfirmedTotal += todo.cves.filter((h) => h.unconfirmed === true).length;
          newTodos.push(mergeTodo(openTodos, todo));
        }

        if (args.with_epss !== false) {
          // Every hit id is asked for, unconfirmed ones included: an EPSS score is a fact about
          // the CVE, and a thin index that leaves the match unconfirmed must not cost the score.
          const cveIds = newTodos.flatMap((t) => t.cves.map((c) => c.cve_id));
          const epss = await fetchEpss(ctx.http, ttl(settings.epssTtlHours), cveIds);
          if (epss.error) epssError = epss.error;
          const scores = epss.scores;
          for (const t of newTodos) {
            for (const c of t.cves) if (scores.has(c.cve_id)) c.epss = scores.get(c.cve_id) ?? null;
            const max = t.cves.map((c) => c.epss).filter((x): x is number => x !== null);
            t.max_epss = max.length > 0 ? Math.max(...max) : null;
          }
        }
      }

      // Anything dismissed stays out of the refreshed set and is carried over untouched, so a
      // dismissal never silently disappears on the next check.
      const dismissed = store.todos.filter((t) => t.status === "dismissed");
      const seen = new Set(newTodos.map((t) => t.id));
      store.todos = [...newTodos, ...dismissed.filter((t) => !seen.has(t.id))];
      store.updated_at = new Date().toISOString();
      store.cve_mode = lookup.stats.mode;
      ctx.store.save(store);

      return ok(
        {
          checked_at: store.updated_at,
          cve_status: cveStatus,
          inventory_size: store.inventory.length,
          programs_with_hits: programsChecked,
          cve_hits: hitsTotal,
          kev_hits: kevHits,
          /**
           * Hits whose version could not be verified (product-name match only). They are carried in
           * the todos but do not lift `max_severity`, so a thin local index never inflates the risk.
           */
          unconfirmed_hits: unconfirmedTotal,
          /**
           * Name matches that never became hits because the version verdict rejected them: a known
           * affected range that excludes the installed version, or the era heuristic (a 2016 CVE
           * against Edge 155). Makes the pre-hit filtering visible instead of silent.
           */
          dropped_by_verdict: droppedByVerdict,
          /** Programs skipped because only a downloaded installer .exe reported them. */
          installer_artifacts_skipped: skippedInstallerArtifacts,
          /** Unscored KEV hits this run completed from NVD (the cached helper); the rest stay marked unenriched. */
          nvd_enriched: nvdEnriched,
          kev: { total: kev.total, from: kev.from, fetched_at: kev.fetched_at },
          /** How the CVE answers were obtained: keyed NVD or the keyless OSV-plus-cache fallback. */
          mode: lookup.stats.mode,
          nvd_key: lookup.stats.mode === "nvd-keyed" ? resolveNvdKey(ctx.config).source : null,
          product_cache: {
            products_cached: lookup.stats.products_cached,
            refreshed: lookup.stats.refreshed,
            deferred: lookup.stats.deferred,
            fetched_at: lookup.stats.fetched_at,
          },
          /**
           * Whether this run's answer may be read as complete (task 4, v0.6.3). A cold or throttled
           * NVD walk leaves products unanswered; that is NOT "no vulnerabilities", and a reader —
           * especially an LLM agent — must re-run after a wait before drawing a conclusion. The
           * existing `cve_status` values are untouched: `checked_data: "incomplete"` is the additive
           * marker that sits next to them.
           */
          completeness: buildCompleteness(lookup.stats, drainActive(cacheDir), cveStatus),
          checked_data: cveStatus === "unknown" ? "unknown" : lookup.stats.pending === 0 ? "complete" : "incomplete",
          /** The cvelist delta index that was merged in this run (loaded in every mode since v0.6.3). */
          cvelist: {
            deprecated: true,
            cves: fallback.byProduct.size > 0 ? fallback.totalCves : 0,
            products: fallback.byProduct.size,
            from: fallback.from,
            fetched_at: fallback.fetched_at,
            index_coverage: {
              local_cves: index.totalCves,
              corpus_estimate: CVELIST_FULL_CORPUS_ESTIMATE,
              percent: Number(((index.totalCves / CVELIST_FULL_CORPUS_ESTIMATE) * 100).toFixed(1)),
            },
          },
          todos: store.todos.length,
          source_errors: [
            kev.error,
            ...(lookup.stats.mode === "keyless-osv+cached"
              // The console hint belongs in the answer too: a keyless run must never read as a
              // claim of completeness.
              ? ["running keyless, not optimal — rate limits apply, results may be less complete (no valid NVD API key — check dashboard)"]
              : []),
            ...lookup.stats.errors,
            index.error,
            epssError,
          ].filter((e): e is string => Boolean(e)),
        },
        cveStatus === "unknown"
          ? `No CVE data reachable: inventory kept, ${String(store.todos.length)} todo(s) unchanged.`
          : `${String(hitsTotal)} CVE hit(s) on ${String(programsChecked)} program(s) [${lookup.stats.mode}], ${String(kevHits)} actively exploited` +
            `${unconfirmedTotal > 0 ? `, ${String(unconfirmedTotal)} unconfirmed (name match only, excluded from severity)` : ""}` +
            `${droppedByVerdict > 0 ? `, ${String(droppedByVerdict)} name match(es) rejected by the version verdict` : ""}` +
            `${skippedInstallerArtifacts > 0 ? `, ${String(skippedInstallerArtifacts)} installer artifact(s) skipped` : ""}. ` +
            `${String(store.todos.length)} todo(s) stored.`,
      );
    },
  },
  {
    name: "cve_detail",
    module: "cves",
    title: "CVE detail",
    description: "Look up a single CVE at NVD API 2.0: description, CVSS, references. Cached for a day.",
    docs:
      "The only place the server calls NVD live. Phase 0 measured the keyless rate limit at four requests per thirty " +
      "seconds, so this is one call per user request by design and the result is cached on disk, not fetched per program.",
    input: z.object({
      cve_id: z.string().regex(/^CVE-\d{4}-\d{4,}$/i).describe("A CVE id, e.g. CVE-2024-21413"),
    }),
    handler: async (args, ctx) => {
      const cveId = String(args.cve_id).toUpperCase();
      const res = await nvdCveDetail(ctx.http, ctx.config.settings.httpTimeoutMs, cveId, resolveNvdKey(ctx.config).key);
      if (!res.data) return fail(`cve_detail for ${cveId}: ${res.error ?? "no answer"}`);

      const body = res.data as { totalResults?: number; vulnerabilities?: unknown[] };
      const first = (body.vulnerabilities ?? [])[0] as
        | {
            cve?: {
              id?: string;
              published?: string;
              vulnStatus?: string;
              descriptions?: { value?: string; lang?: string }[];
              metrics?: Record<string, unknown>[];
              references?: { url?: string }[];
            };
          }
        | undefined;
      if (!first?.cve) return fail(`cve_detail: NVD returned no entry for ${cveId}`);

      const cve = first.cve;
      const m = cve.metrics ?? {};
      const scoreOf = (key: string): number | undefined => {
        const entry = (m as Record<string, { cvssData?: { baseScore?: number } }[]>)[key]?.[0];
        const score = entry?.cvssData?.baseScore;
        return typeof score === "number" ? score : undefined;
      };
      const v31 = scoreOf("cvssMetricV31");
      const v4 = scoreOf("cvssMetricV40");
      // NVD mixes translated ADP descriptions into the list (a Spanish probe showed
      // “Vulnerabilidad de ejecución remota…”), so the english entry is preferred and only the
      // first one is kept — joining all of them reads like noise.
      const descriptions = cve.descriptions ?? [];
      const english = descriptions.find((d) => String(d.lang ?? "").toLowerCase().startsWith("en"));
      const description = String((english ?? descriptions[0])?.value ?? "").replace(/\s+/g, " ").trim();

      return ok(
        {
          cve_id: cveId,
          published: cve.published ?? null,
          vuln_status: cve.vulnStatus ?? null,
          description: description.slice(0, 1000),
          cvss: v4 ?? v31 ?? null,
          references: [...new Set((cve.references ?? []).map((r) => String(r.url ?? "")))].slice(0, 10),
          source: "nvd",
          fetched_from: res.from,
        },
        `${cveId}: ${String(v4 ?? v31 ?? "no CVSS")}${description ? ` — ${description.slice(0, 80)}` : ""}`,
      );
    },
  },
];


