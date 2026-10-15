import { createHash } from "node:crypto";

import { severityOf } from "../cves/engine.js";
import { compareVersions, normName, normVersion, productFamily } from "../../utils/matching.js";
import type { Assessment, CveHit, InventoryEntry, MatchConfidence, Todo, TodoStatus, TodoVersion } from "../../model.js";

/**
 * The fixed assessment schema of §5.
 *
 * It lives in one place because the sampling prompt and the `save_assessment` input must produce
 * byte-for-byte the same shape, and a human reading the ToDo list later should not have to know
 * which path produced a verdict.
 */
export const ASSESSMENT_SCHEMA = {
  type: "object",
  required: ["exe_swap_only", "new_setup_needed", "breaking_change_expected", "reason", "confidence"],
  properties: {
    exe_swap_only: {
      type: "boolean",
      description: "(a) The fix is reached by replacing the .exe/file alone, no installer involved.",
    },
    new_setup_needed: {
      type: "boolean",
      description: "(b) A new setup package from the vendor has to be downloaded and run.",
    },
    breaking_change_expected: {
      type: "boolean",
      description: "(c) The update is expected to break configuration, plugins, or file associations.",
    },
    affected_part: {
      type: ["string", "null"],
      description: "(d) When only part of a suite is affected, name that part; otherwise null.",
    },
    reason: { type: "string", description: "Short justification in plain words." },
    confidence: { type: "string", enum: ["exact", "high", "medium", "low"] },
  },
} as const;

/**
 * Textual form of the schema appended to the sampling prompt.
 *
 * MCP sampling takes a prompt, not a JSON schema, so the schema has to be spelled out in the text
 * and the answer parsed back; keeping the two in one constant is what stops them from drifting.
 */
export const ASSESSMENT_PROMPT_RULES = `Answer with a single JSON object and nothing else, with exactly these keys:
- "exe_swap_only" (boolean): (a) is the fix a plain .exe/file replacement?
- "new_setup_needed" (boolean): (b) is a new setup package from the vendor required?
- "breaking_change_expected" (boolean): (c) is a breaking change expected?
- "affected_part" (string or null): (d) if only a part program of a suite is affected, name it.
- "reason" (string): a short justification.
- "confidence" (one of "exact", "high", "medium", "low").`;

/** The evidence package the server hands a client that has to do the assessing itself. */
export interface EvidencePackage {
  todo_id: string;
  program: string;
  version: string | null;
  publisher: string | null;
  install_sources: string[];
  package_ids: string[];
  cve_count: number;
  kev_cves: string[];
  fix_version: string | null;
  max_severity: Todo["max_severity"];
  max_cvss: number | null;
  max_epss: number | null;
  match_confidence: MatchConfidence;
  axes: Record<string, string>;
}

export function buildEvidence(todo: Todo, entry: InventoryEntry | undefined): EvidencePackage {
  return {
    todo_id: todo.id,
    program: todo.program,
    version: todo.version,
    publisher: todo.publisher ?? entry?.publisher ?? null,
    install_sources: [
      ...new Set([
        ...(entry?.sources.map((s) => s.install_source).filter((x): x is string => Boolean(x)) ?? []),
        ...(entry?.sources.map((s) => s.source) ?? []),
      ]),
    ],
    package_ids: entry?.package_ids ?? [],
    cve_count: todo.cves.length,
    kev_cves: todo.cves.filter((c) => c.kev).map((c) => c.cve_id),
    fix_version: todo.fix_version,
    max_severity: todo.max_severity,
    max_cvss: todo.max_cvss,
    max_epss: todo.max_epss,
    match_confidence: todo.match_confidence,
    axes: {
      a: "replace the .exe/file only",
      b: "a new setup from the vendor is needed",
      c: "a breaking change is expected",
      d: "only a part program of a suite is affected (name it)",
    },
  };
}

/**
 * A todo id that survives a re-scan of the same program.
 *
 * Deriving it from the inventory id plus the sorted CVE set means the same finding keeps its id and
 * its status across runs, which is what makes `dismissed` mean something over days.
 */
export function todoId(inventoryId: string, cveIds: string[]): string {
  const hash = createHash("sha1").update(`${inventoryId}|${[...cveIds].sort().join(",")}`).digest("hex");
  return `todo-${hash.slice(0, 10)}`;
}

/**
 * Aggregates a fresh todo out of a program and its hits.
 *
 * `merge` is set when the todo stands for several installed versions of one product family: it then
 * carries a family-stable id and the list of member versions instead of the single entry's.
 */
export function buildTodo(
  entry: InventoryEntry,
  hits: CveHit[],
  confidence: MatchConfidence,
  cveStatus: Todo["cve_status"],
  merge?: { stable_id: string; inventory_id: string; versions: TodoVersion[] },
): Todo {
  const now = new Date().toISOString();
  const severities: Todo["max_severity"][] = ["none", "low", "medium", "high", "critical"];

  let maxSeverity: Todo["max_severity"] = "none";
  let maxCvss: number | null = null;
  let maxEpss: number | null = null;
  let anyKev = false;
  let kevConfirmed = false;

  for (const h of hits) {
    if (h.kev) anyKev = true;
    // A score is a fact about the CVE, so the columns stay useful for every hit that carries one.
    if (h.cvss !== null && (maxCvss === null || h.cvss > maxCvss)) maxCvss = h.cvss;
    if (h.epss !== null && (maxEpss === null || h.epss > maxEpss)) maxEpss = h.epss;
    // The *rating* however ignores an unconfirmed hit (its version range could not be checked):
    // "the product name is in KEV" alone is not a finding, so it must not promote the entry.
    if (h.unconfirmed === true) continue;
    if (h.kev) kevConfirmed = true;
    if (severities.indexOf(severityOf(h.cvss)) > severities.indexOf(maxSeverity)) maxSeverity = severityOf(h.cvss);
  }
  if (kevConfirmed && severities.indexOf(maxSeverity) < severities.indexOf("high")) maxSeverity = "high";

  const fix = pickFix(hits);

  const unconfirmed = hits.filter((h) => h.unconfirmed === true).map((h) => h.cve_id);

  return {
    id: merge?.stable_id ?? todoId(entry.id, hits.map((h) => h.cve_id)),
    inventory_id: merge?.inventory_id ?? entry.id,
    program: entry.name,
    version: entry.version,
    publisher: entry.publisher,
    cves: hits,
    /** KEV name matches whose version range could not be verified, listed apart from the findings. */
    unconfirmed_cves: unconfirmed,
    max_severity: maxSeverity,
    max_cvss: maxCvss,
    any_kev: anyKev,
    kev_confirmed: kevConfirmed,
    ...(merge !== undefined ? { versions: merge.versions } : {}),
    max_epss: maxEpss,
    fix_version: fix,
    match_confidence: confidence,
    cve_status: cveStatus,
    status: "open",
    assessment: null,
    created_at: now,
    updated_at: now,
  };
}

/** The newest version named as a fix, since that is the one a patch would actually install. */
function pickFix(hits: CveHit[]): string | null {
  let best: string | null = null;
  for (const h of hits) {
    const v = h.fixed_version;
    if (!v) continue;
    if (best === null || compareVersions(v, best) > 0) best = v;
  }
  return best;
}

/**
 * Merges a freshly computed todo into the existing list.
 *
 * An id that already exists keeps its status, its timestamps and an assessment a human or the model
 * already produced; only the CVE facts are refreshed. A dismissed finding that comes back with a
 * *new* CVE set gets a new id and is therefore open again, which is the intended behaviour: the
 * dismissal belonged to the older set of facts.
 */
export function mergeTodo(existing: Todo[], fresh: Todo): Todo {
  const now = new Date().toISOString();
  const prev = existing.find((t) => t.id === fresh.id);
  if (!prev) return fresh;

  const cves: CveHit[] = [...prev.cves];
  for (const h of fresh.cves) {
    const before = cves.find((c) => c.cve_id === h.cve_id);
    if (before) Object.assign(before, h);
    else cves.push(h);
  }

  const merged: Todo = {
    ...fresh,
    cves,
    status: prev.status,
    assessment: prev.assessment,
    created_at: prev.created_at,
    updated_at: now,
  };
  return merged;
}

/**
 * Whether a to-do carries at least one **verified** KEV finding.
 *
 * Written for stores that predate the field, so an old row is re-derived instead of read as
 * `undefined` and ranked below every confirmed one.
 */
export function kevConfirmedOf(t: Todo): boolean {
  return t.kev_confirmed ?? t.cves.some((c) => c.kev && c.unconfirmed !== true);
}

/** Whether a to-do carries at least one hit whose version was verified. `list_todos` ranks on it. */
export function hasConfirmedFinding(t: Todo): boolean {
  return t.cves.some((c) => c.unconfirmed !== true);
}

/**
 * The ranking of `list_todos` and the dashboard, in one place so the two views agree:
 * a verified KEV finding first, then any other verified finding, then severity, CVSS and EPSS. A
 * to-do whose hits are all unverified name matches therefore never outranks a confirmed one.
 */
export function compareTodoRank(a: Todo, b: Todo): number {
  return (
    Number(kevConfirmedOf(b)) - Number(kevConfirmedOf(a)) ||
    Number(hasConfirmedFinding(b)) - Number(hasConfirmedFinding(a)) ||
    severityRank(b.max_severity) - severityRank(a.max_severity) ||
    (b.max_cvss ?? 0) - (a.max_cvss ?? 0) ||
    (b.max_epss ?? 0) - (a.max_epss ?? 0) ||
    a.program.localeCompare(b.program, "en")
  );
}

/**
 * The confidence a group of hits is rated with: only confirmed hits decide it, so an unverifiable
 * name match never pulls a certain finding down to "low".
 */
export function ratingConfidence(hits: CveHit[]): MatchConfidence {
  const confirmed = hits.filter((h) => h.unconfirmed !== true);
  const rated = confirmed.length > 0 ? confirmed : hits;
  return rated.some((h) => h.match_confidence === "low")
    ? "low"
    : rated.every((h) => h.match_confidence === "exact")
      ? "exact"
      : rated.some((h) => h.match_confidence === "high")
        ? "high"
        : "medium";
}

/**
 * Groups the matched programs into to-dos by **product family**.
 *
 * Two installed versions of one product ("Microsoft Edge" 152 and 155) are the same finding: the
 * members merge into one to-do whose `versions` list carries every installed version, newest first,
 * so the list shows one row per product instead of a near-duplicate per version. An empty family
 * leaves an entry as its own group, exactly like before.
 */
export function groupMatchesIntoTodos(
  matches: { family: string; entry: InventoryEntry; hits: CveHit[]; cveStatus: Todo["cve_status"] }[],
): Todo[] {
  interface Group {
    rep: InventoryEntry;
    members: InventoryEntry[];
    hits: Map<string, CveHit>;
    cveStatus: Todo["cve_status"];
  }
  const groups = new Map<string, Group>();

  for (const m of matches) {
    const key = m.family === "" ? `entry:${m.entry.id}` : `family:${m.family}`;
    const g = groups.get(key);
    if (!g) {
      groups.set(key, { rep: m.entry, members: [m.entry], hits: new Map(m.hits.map((h) => [h.cve_id, h])), cveStatus: m.cveStatus });
      continue;
    }
    g.members.push(m.entry);
    for (const h of m.hits) {
      const first = g.hits.get(h.cve_id);
      // A KEV marker found through one member applies to the shared product; the hit object itself
      // stays the first one, so exactly one row per CVE remains.
      if (first) first.kev = first.kev || h.kev;
      else g.hits.set(h.cve_id, h);
    }
    // The newest installed version becomes the representative row of the group.
    const a = normVersion(m.entry.version ?? "");
    const b = normVersion(g.rep.version ?? "");
    if ((a !== "" && b === "") || (a !== "" && b !== "" && compareVersions(a, b) > 0)) g.rep = m.entry;
  }

  const todos: Todo[] = [];
  for (const [key, g] of groups) {
    const hits = [...g.hits.values()];
    const rep = g.rep;
    const merge =
      g.members.length > 1
        ? {
            stable_id: todoId(`family:${normName(rep.name)}`, hits.map((h) => h.cve_id)),
            inventory_id: key,
            versions: [...g.members]
              .sort((x, y) => compareVersions(normVersion(y.version ?? ""), normVersion(x.version ?? "")))
              .map((e) => ({ inventory_id: e.id, program: e.name, version: e.version })),
          }
        : undefined;
    todos.push(buildTodo(rep, hits, ratingConfidence(hits), g.cveStatus, merge));
  }
  return todos;
}

export function normalizeAssessment(input: Record<string, unknown>, by: Assessment["assessed_by"]): Assessment {
  const conf = String(input.confidence ?? "medium") as MatchConfidence;
  return {
    exe_swap_only: Boolean(input.exe_swap_only),
    new_setup_needed: Boolean(input.new_setup_needed),
    breaking_change_expected: Boolean(input.breaking_change_expected),
    affected_part: typeof input.affected_part === "string" && input.affected_part !== "" ? input.affected_part : null,
    reason: String(input.reason ?? ""),
    confidence: (["exact", "high", "medium", "low"] as const).includes(conf) ? conf : "medium",
    assessed_by: by,
    assessed_at: new Date().toISOString(),
  };
}

/** Sorting weight so `list_todos` can order KEV first, then severity, then EPSS. */
export function severityRank(s: TodoStatus | Todo["max_severity"]): number {
  const order: Record<string, number> = { critical: 5, high: 4, medium: 3, low: 2, none: 1, open: 0, assessed: 0, dismissed: 0 };
  return order[s] ?? 0;
}
