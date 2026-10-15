import { createHash } from "node:crypto";

import { dedupKey, normName, normVersion, similarity } from "../../utils/matching.js";
import type { InventoryEntry, ProgramSource, RawProgram } from "../../model.js";

/**
 * Merge of the three sources into one list.
 *
 * The key is the normalised (product, version), so the same program found in HKLM, in `winget list`
 * and as a portable `.exe` becomes one entry carrying three sources. A stable id derived from that
 * key means the ToDo list can point at an entry across runs.
 */
export function dedupePrograms(programs: RawProgram[], previous: InventoryEntry[]): InventoryEntry[] {
  const now = new Date().toISOString();
  const prevById = new Map(previous.map((e) => [e.id, e]));
  const byKey = new Map<string, InventoryEntry>();

  for (const p of programs) {
    const key = dedupKey(p.name, p.version);
    if (key === "|") continue;

    const existing = byKey.get(key);
    if (existing) {
      if (!existing.sources.some((s) => s.source === p.source && s.name === p.name && s.version === (p.version ?? ""))) {
        existing.sources.push(toSource(p));
      }
      if (p.package_id && !existing.package_ids.includes(p.package_id)) existing.package_ids.push(p.package_id);
      if (p.path && !existing.paths.includes(p.path)) existing.paths.push(p.path);
      if ((!existing.publisher || existing.publisher === "") && p.publisher) existing.publisher = p.publisher;
      continue;
    }

    const id = entryId(key);
    const before = prevById.get(id);
    byKey.set(key, {
      id,
      name: p.name,
      version: p.version,
      publisher: p.publisher,
      sources: [toSource(p)],
      package_ids: p.package_id ? [p.package_id] : [],
      paths: p.path ? [p.path] : [],
      match_hint: null,
      first_seen: before?.first_seen ?? now,
      last_seen: now,
    });
  }

  // Derived from the accumulated sources, so the order the sources arrived in cannot pick a weaker
  // identity than the best one that was available.
  for (const e of byKey.values()) {
    e.match_hint = e.package_ids[0] ?? normName(e.name);
  }

  return [...byKey.values()].sort((a, b) => a.name.localeCompare(b.name, "en"));
}

function toSource(p: RawProgram): ProgramSource {
  return {
    source: p.source,
    name: p.name,
    version: p.version,
    publisher: p.publisher,
    package_id: p.package_id,
    path: p.path,
    registry_key: p.registry_key,
    install_source: p.install_source,
    uninstall_string: p.uninstall_string,
  };
}

function entryId(key: string): string {
  return createHash("sha1").update(key).digest("hex").slice(0, 12);
}

/**
 * Counters per source plus the dedup result, which is what `scan_inventory` reports.
 */
export function countSources(programs: RawProgram[]): Record<string, number> {
  const counts: Record<string, number> = { registry: 0, winget: 0, portable: 0 };
  for (const p of programs) {
    counts[p.source] = (counts[p.source] ?? 0) + 1;
  }
  return counts;
}

/**
 * The best identity a program offers for CVE matching, ranked.
 *
 * A winget package id is an authoritative product identifier, so it beats any name; a registry
 * display name with a version is next; a bare portable product name is the weakest.
 */
export function identityScore(entry: InventoryEntry): { hint: string; confidence: "exact" | "high" | "medium" } {
  if (entry.package_ids.length > 0) return { hint: entry.package_ids[0] ?? "", confidence: "exact" };
  if (entry.version && normName(entry.name).length > 2) return { hint: entry.name, confidence: "high" };
  return { hint: entry.name, confidence: "medium" };
}

/** Whether two names are the same product, used to rescue matches the exact key missed. */
export function sameProduct(a: string, b: string): boolean {
  return similarity(a, b) >= 0.88;
}

export { normVersion };
