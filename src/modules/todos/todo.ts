import { createHash } from "node:crypto";

import { severityOf } from "../cves/engine.js";
import { compareVersions } from "../../utils/matching.js";
import type { Assessment, CveHit, InventoryEntry, MatchConfidence, Todo, TodoStatus } from "../../model.js";

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

/** Aggregates a fresh todo out of a program and its hits. */
export function buildTodo(
  entry: InventoryEntry,
  hits: CveHit[],
  confidence: MatchConfidence,
  cveStatus: Todo["cve_status"],
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
    id: todoId(entry.id, hits.map((h) => h.cve_id)),
    inventory_id: entry.id,
    program: entry.name,
    version: entry.version,
    publisher: entry.publisher,
    cves: hits,
    /** KEV name matches whose version range could not be verified, listed apart from the findings. */
    unconfirmed_cves: unconfirmed,
    max_severity: maxSeverity,
    max_cvss: maxCvss,
    any_kev: anyKev,
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
