import { z } from "zod";

import type { ToolDefinition } from "../../types.js";
import { fail, ok } from "../../utils/result.js";
import { fetchEpss, kevForProduct, loadKev, loadProductIndex, nvdCveDetail } from "../cves/feeds.js";
import { matchProgram } from "../cves/engine.js";
import { buildTodo, mergeTodo } from "../todos/todo.js";

export const cveTools: ToolDefinition[] = [
  {
    name: "check_cves",
    module: "cves",
    title: "Check CVEs",
    description:
      "Match the stored inventory against the local CVE sources (cvelistV5 delta, CISA KEV, EPSS) and fill the ToDo list. Never requires the network.",
    docs:
      "Offline rule: the run never depends on the network. Every source is read from its disk cache when the cache is " +
      "fresh; when the network is down the expired cache is still used, and only a cold cache with no network yields " +
      "cve_status: \"unknown\" with the inventory left untouched by the CVE layer.\n" +
      "The cvelistV5 delta is accumulated into a local index on every run that finds a newer release, so coverage grows " +
      "over days without the full 602 MB download. The answer reports how much the index currently covers.\n" +
      "Matching is name-based and carries a confidence per hit; an unsure match is reported with match_confidence and " +
      "never counted as a certain hit.",
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

      const [kev, index] = await Promise.all([
        loadKev(ctx.http, ttl(settings.kevTtlHours)),
        loadProductIndex(ctx.http, ttl(settings.cvelistTtlHours), cacheDir),
      ]);

      const dataAvailable = index.byProduct.size > 0 || kev.byCve.size > 0;
      const cveStatus: "checked" | "unknown" = dataAvailable ? "checked" : "unknown";

      const openTodos = store.todos.filter((t) => t.status !== "dismissed");
      const newTodos: import("../../model.js").Todo[] = [];
      let programsChecked = 0;
      let hitsTotal = 0;
      let kevHits = 0;

      if (dataAvailable) {
        for (const entry of store.inventory) {
          const { hits } = matchProgram(entry, index, kev);
          if (hits.length === 0) continue;
          programsChecked += 1;
          hitsTotal += hits.length;
          kevHits += hits.filter((h) => h.kev).length;

          const confidence = hits.some((h) => h.match_confidence === "low")
            ? "low"
            : hits.every((h) => h.match_confidence === "exact")
              ? "exact"
              : hits.some((h) => h.match_confidence === "high")
                ? "high"
                : "medium";

          const todo = buildTodo(entry, hits, confidence, cveStatus);
          newTodos.push(mergeTodo(openTodos, todo));
        }

        if (args.with_epss !== false) {
          const cveIds = newTodos.flatMap((t) => t.cves.map((c) => c.cve_id));
          const scores = await fetchEpss(ctx.http, ttl(settings.epssTtlHours), cveIds);
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
      ctx.store.save(store);

      return ok(
        {
          checked_at: store.updated_at,
          cve_status: cveStatus,
          inventory_size: store.inventory.length,
          programs_with_hits: programsChecked,
          cve_hits: hitsTotal,
          kev_hits: kevHits,
          kev: { total: kev.total, from: kev.from, fetched_at: kev.fetched_at },
          cvelist: {
            cves: index.totalCves,
            products: index.products,
            from: index.from,
            fetched_at: index.fetched_at,
          },
          todos: store.todos.length,
          source_errors: [kev.error, index.error].filter((e): e is string => Boolean(e)),
        },
        cveStatus === "unknown"
          ? `No CVE data reachable: inventory kept, ${String(store.todos.length)} todo(s) unchanged.`
          : `${String(hitsTotal)} CVE hit(s) on ${String(programsChecked)} program(s), ${String(kevHits)} actively exploited. ${String(store.todos.length)} todo(s) stored.`,
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
      const res = await nvdCveDetail(ctx.http, ctx.config.settings.httpTimeoutMs, cveId);
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
      const description = (cve.descriptions ?? []).map((d) => String(d.value ?? "")).join(" ").replace(/\s+/g, " ").trim();

      return ok(
        {
          cve_id: cveId,
          published: cve.published ?? null,
          vuln_status: cve.vulnStatus ?? null,
          description: description.slice(0, 1000),
          cvss: v4 ?? v31 ?? null,
          references: (cve.references ?? []).slice(0, 10).map((r) => String(r.url ?? "")),
          source: "nvd",
          fetched_from: res.from,
        },
        `${cveId}: ${String(v4 ?? v31 ?? "no CVSS")}${description ? ` — ${description.slice(0, 80)}` : ""}`,
      );
    },
  },
];


