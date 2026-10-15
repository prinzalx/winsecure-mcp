import { z } from "zod";

import type { ToolDefinition } from "../../types.js";
import { fail, ok } from "../../utils/result.js";
import { countSources, dedupePrograms } from "./dedupe.js";
import { findPortablePrograms, fixedRoots, readRegistryPrograms, readWingetPrograms } from "./sources.js";
import type { RawProgram } from "../../model.js";

const SOURCES = ["registry", "winget", "portable"] as const;

/**
 * Which sources a run should read.
 *
 * Omitted means all three, which is the normal case; a caller that only wants the cheap sources can
 * leave the portable walk out, since that is the one that touches the filesystem.
 */
function wanted(args: Record<string, unknown>): Set<string> {
  const list = args.sources;
  if (!Array.isArray(list) || list.length === 0) return new Set(SOURCES);
  return new Set(list.map(String));
}

export const inventoryTools: ToolDefinition[] = [
  {
    name: "scan_inventory",
    module: "inventory",
    title: "Scan inventory",
    description:
      "Refresh the installed-software inventory from the registry, `winget list` and a portable .exe scan. " +
      "Returns per-source counters and the deduplicated result.",
    docs:
      "Three sources, merged under a normalised (product, version) key: the Uninstall registry keys of HKLM and HKCU " +
      "including WOW6432Node, `winget list` for store and winget-managed apps, and a walk over the fixed drives for " +
      ".exe files that carry version information.\n" +
      "A source that fails does not fail the run: its counter comes back 0 with the reason in `source_errors`, and a " +
      "directory the process may not enter is skipped rather than reported.\n" +
      "Read the counters together with `source_errors`: every source that contributed nothing is reported there, so a " +
      "host the server cannot see (no powershell.exe, no fixed drive) says so instead of answering \"0 programs\".\n" +
      "The portable walk is the expensive one. It is bounded by portableMaxResults and portableTimeoutMs in the config, " +
      "and when it is cut off the report says so and still lists the paths it visited.",
    input: z.object({
      sources: z
        .array(z.enum(SOURCES))
        .optional()
        .describe("Which sources to read. Defaults to all three"),
      roots: z.array(z.string()).optional().describe("Drive roots for the portable scan. Defaults to the fixed disks"),
    }),
    handler: async (args, ctx) => {
      const want = wanted(args);
      const settings = ctx.config.settings;
      const errors: Record<string, string> = {};
      const programs: RawProgram[] = [];
      const counters: Record<string, number> = { registry: 0, winget: 0, portable: 0 };
      const report: Record<string, unknown> = {};

      if (want.has("registry")) {
        const r = await readRegistryPrograms();
        programs.push(...r.programs);
        counters.registry = r.programs.length;
        if (r.error) errors.registry = r.error;
      }

      if (want.has("winget")) {
        const r = await readWingetPrograms();
        programs.push(...r.programs);
        counters.winget = r.programs.length;
        if (r.error) errors.winget = r.error;
      }

      if (want.has("portable")) {
        let roots: string[] = [];
        if (Array.isArray(args.roots) && args.roots.length > 0) {
          roots = args.roots.map(String);
        } else {
          const foundRoots = await fixedRoots();
          roots = foundRoots.roots;
          if (foundRoots.error) errors.portable_roots = foundRoots.error;
        }
        const r = await findPortablePrograms({
          roots,
          excludes: settings.portableExcludes,
          maxResults: settings.portableMaxResults,
          timeoutMs: settings.portableTimeoutMs,
        });
        const kept = r.programs.slice(0, settings.portableMaxResults);
        counters.portable = kept.length;
        if (r.error) errors.portable = r.error;
        report.portable = {
          exe_files_read: r.scanned,
          with_version_info: r.programs.length,
          roots,
          timed_out: r.timedOut,
          cut_off: r.programs.length > kept.length,
          skipped_paths: r.skipped_paths,
        };
        programs.push(...kept);
      }

      // A requested source that contributed nothing is always reported, with or without an
      // exception behind it. Without this the answer was "scan succeeded, 0 programs" on a machine
      // where the server could not see Windows at all.
      for (const source of SOURCES) {
        if (want.has(source) && (counters[source] ?? 0) === 0 && errors[source] === undefined) {
          errors[source] = "no entries reported";
        }
      }

      const store = ctx.store.load();
      const entries = dedupePrograms(programs, store.inventory);
      store.inventory = entries;
      store.updated_at = new Date().toISOString();
      ctx.store.save(store);

      const problemKeys = Object.keys(errors);
      const counterLine = `registry ${String(counters.registry ?? 0)}, winget ${String(counters.winget ?? 0)}, portable ${String(counters.portable ?? 0)}`;

      return ok(
        {
          scanned_at: store.updated_at,
          sources_read: [...want],
          counters,
          deduplicated: entries.length,
          duplicates_merged: Math.max(0, programs.length - entries.length),
          /** Set when a source that was asked for contributed nothing; the scan is then degraded, not clean. */
          degraded: problemKeys.length > 0,
          source_errors: problemKeys.length > 0 ? errors : undefined,
          report,
          stored_in: ctx.store.path,
        },
        `${String(entries.length)} programs after deduplication (${counterLine}).` +
          (problemKeys.length > 0
            ? ` Degraded: ${problemKeys.map((k) => `${k}: ${errors[k]}`).join("; ")}`
            : ""),
      );
    },
  },
  {
    name: "get_program",
    module: "inventory",
    title: "Get program",
    description:
      "Detail view of one inventory entry: every source that reported it, its paths, versions and the CVEs assigned to it.",
    docs:
      "Searches the stored inventory by a case-insensitive substring of the name, or by the exact inventory id.\n" +
      "With `with_cves: true` the currently open CVE hits are included, which is the quickest way to see one program's " +
      "whole security picture without reading the whole ToDo list.\n" +
      "Several programs can match a substring; the answer then lists them all up to `limit` instead of picking one.",
    input: z.object({
      program: z.string().min(1).describe("Name substring or the exact inventory id"),
      with_cves: z.boolean().optional().describe("Include the CVE hits of each match. Defaults to true"),
      limit: z.number().int().positive().max(50).optional().describe("Maximum matches to return. Defaults to 10"),
    }),
    handler: async (args, ctx) => {
      const needle = String(args.program);
      const limit = typeof args.limit === "number" ? args.limit : 10;
      const store = ctx.store.load();

      const lower = needle.toLowerCase();
      const matches = store.inventory.filter((e) => e.id === needle || e.name.toLowerCase().includes(lower)).slice(0, limit);

      if (matches.length === 0) {
        return fail(`No inventory entry matching "${needle}" — run scan_inventory or check the spelling`);
      }

      const withCves = args.with_cves !== false;
      const todosOf = (id: string) => store.todos.filter((t) => t.inventory_id === id && t.status !== "dismissed");

      return ok(
        {
          matches: matches.map((e) => ({
            id: e.id,
            name: e.name,
            version: e.version,
            publisher: e.publisher,
            sources: e.sources,
            package_ids: e.package_ids,
            paths: e.paths,
            first_seen: e.first_seen,
            last_seen: e.last_seen,
            cves: withCves
              ? todosOf(e.id).flatMap((t) =>
                  t.cves.map((c) => ({
                    cve_id: c.cve_id,
                    severity: c.severity,
                    cvss: c.cvss,
                    kev: c.kev,
                    epss: c.epss,
                    fixed_version: c.fixed_version,
                    match_confidence: c.match_confidence,
                    todo_status: t.status,
                  })),
                )
              : undefined,
          })),
          count: matches.length,
        },
        `${String(matches.length)} matching ${matches.length === 1 ? "program" : "programs"}: ${matches
          .map((m) => `${m.name} ${m.version ?? ""}`.trim())
          .join(", ")}`,
      );
    },
  },
];


