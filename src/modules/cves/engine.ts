import { compareVersions, normName, normVersion, squeeze } from "../../utils/matching.js";
import type { ProductIndex, KevIndex, CveRecord } from "./feeds.js";
import { kevForProduct } from "./feeds.js";
import type { CveHit, InventoryEntry, MatchConfidence } from "../../model.js";

/**
 * Candidate product names for one inventory entry.
 *
 * Order matters and each candidate carries its own confidence: an exact normalised display name is
 * the strongest, a winget package id's last segment is next (it is a real identifier but from a
 * different naming scheme than the CVE data), then the alias table, then a suffix-stripped name.
 * Nothing here guesses silently — the confidence travels with every hit.
 */
export function candidates(entry: InventoryEntry): { name: string; confidence: MatchConfidence }[] {
  const out: { name: string; confidence: MatchConfidence }[] = [];
  const seen = new Set<string>();
  const push = (name: string, confidence: MatchConfidence): void => {
    const key = normName(name);
    if (key === "" || seen.has(key)) return;
    seen.add(key);
    out.push({ name, confidence });
  };

  push(entry.name, "high");

  for (const id of entry.package_ids) {
    const tail = squeeze(id.split(".").slice(1).join(".") || id).replace(/[-_]/g, " ");
    push(tail, "high");
    push(id.replace(/[._]/g, " "), "medium");
  }

  // Strip trailing version-ish and marketing tokens from the display name.
  const stripped = squeeze(
    normName(entry.name)
      .replace(/\b\d{4}\b/g, " ")
      .replace(/\b\d+(\.\d+)+\b/g, " "),
  );
  push(stripped, "medium");

  return out;
}

/**
 * Is this installed version inside the CVE's affected range?
 *
 * Ranges in cvelistV5 are version strings of type "custom", which are not always comparable (a
 * "1.1.1x" is not semver). Therefore an unparseable bound is treated as *matching*: a possible hit
 * with a lower confidence beats a false negative in a security tool.
 */
export function versionAffected(installed: string | null, rec: CveRecord): { affected: boolean; exact: boolean } {
  if (!installed) return { affected: true, exact: false };
  const v = normVersion(installed);
  if (v === "") return { affected: true, exact: false };

  const below = rec.range_below ? normVersion(rec.range_below) : null;
  const from = rec.range_from ? normVersion(rec.range_from) : null;

  if (below && isNumericish(below)) {
    if (compareVersions(v, below) >= 0) return { affected: false, exact: true };
  } else if (below) {
    return { affected: true, exact: false };
  }

  if (from && isNumericish(from) && compareVersions(v, from) < 0) {
    return { affected: false, exact: true };
  }

  // Reached when the installed version sits inside the range. It counts as verified only when every
  // bound the record carries is comparable, so a one-sided numeric range does verify a version below
  // its upper bound, while a record with no bounds at all does not.
  const bounds = [below, from].filter((b): b is string => b !== null);
  return { affected: true, exact: bounds.length > 0 && bounds.every(isNumericish) };
}

function isNumericish(v: string): boolean {
  return /^\d+(\.\d+){0,4}/.test(v) && !/[a-z]/i.test(v.replace(/^v/i, ""));
}

/**
 * The CVE hits for one program, from the local product index plus the KEV overlay.
 *
 * `checked` says whether real CVE data was available at all. When it was not, the caller marks the
 * todo `cve_status: "unknown"` instead of reporting an empty hit list as "no vulnerabilities".
 */
export function matchProgram(
  entry: InventoryEntry,
  index: ProductIndex,
  kev: KevIndex,
): { hits: CveHit[]; checked: boolean; data_from: string } {
  const checked = index.byProduct.size > 0 || kev.byCve.size > 0;
  if (!checked) return { hits: [], checked: false, data_from: "none" };

  const byId = new Map<string, CveHit>();

  for (const cand of candidates(entry)) {
    const records = index.byProduct.get(normName(cand.name)) ?? [];
    for (const rec of records) {
      const verdict = versionAffected(entry.version, rec);
      if (!verdict.affected) continue;
      const existing = byId.get(rec.cve_id);
      if (existing) {
        if (rank(cand.confidence) > rank(existing.match_confidence)) existing.match_confidence = cand.confidence;
        continue;
      }
      byId.set(rec.cve_id, {
        cve_id: rec.cve_id,
        cvss: rec.cvss,
        severity: sev(rec.cvss),
        kev: false,
        kev_due_date: null,
        epss: null,
        fixed_version: rec.fixed_version,
        matched_by: "cvelist_product",
        match_confidence: verdict.exact ? cand.confidence : demote(cand.confidence),
        summary: rec.summary,
        published: rec.published,
        ...(rec.cvss != null ? { cvss_source: "cvelist" as const } : {}),
      });
    }
  }

  // KEV is an overlay: it can promote a hit the index missed, and it always marks exploitation.
  //
  // The KEV feed itself carries no version range, so a KEV entry the product index does not know is
  // verified against the local CVE record by CVE id. Without that check a name match alone produces
  // false positives (Chrome 120 hit CVE-2020-16017, which only affects Chrome < 86).
  for (const kevEntry of kevForProduct(kev, entry.name)) {
    const hit = byId.get(kevEntry.cve_id);
    if (hit) {
      hit.kev = true;
      hit.kev_due_date = kevEntry.due_date;
      continue;
    }
    const detail = index.byCve?.get(kevEntry.cve_id) ?? null;

    // A known range that excludes the installed version drops the hit entirely.
    const verdict = detail ? versionAffected(entry.version, detail) : null;
    if (verdict && !verdict.affected) continue;

    // No record, or bounds that cannot be compared: the version was not verified, so the hit stays
    // unconfirmed and is reported apart instead of lifting the severity of the whole to-do.
    const unconfirmed = verdict === null || !verdict.exact;

    byId.set(kevEntry.cve_id, {
      cve_id: kevEntry.cve_id,
      cvss: detail?.cvss ?? null,
      severity: sev(detail?.cvss ?? null),
      kev: true,
      kev_due_date: kevEntry.due_date,
      epss: null,
      fixed_version: detail?.fixed_version ?? null,
      matched_by: "kev_product",
      match_confidence: unconfirmed ? "low" : "medium",
      summary: detail?.summary ?? kevEntry.name,
      published: detail?.published ?? null,
      ...(unconfirmed ? { unconfirmed: true } : {}),
      ...(detail?.cvss != null ? { cvss_source: "cvelist" as const } : {}),
    });
  }

  return { hits: [...byId.values()], checked, data_from: index.from !== "none" ? index.from : kev.from };
}

export function hitsFromKevOnly(entry: InventoryEntry, kev: KevIndex): CveHit[] {
  return kevForProduct(kev, entry.name).map((k) => ({
    cve_id: k.cve_id,
    cvss: null,
    severity: "none",
    kev: true,
    kev_due_date: k.due_date,
    epss: null,
    fixed_version: null,
    matched_by: "kev_product" as const,
    match_confidence: "medium" as MatchConfidence,
    summary: k.name,
    published: null,
  }));
}

function rank(c: MatchConfidence): number {
  return { low: 0, medium: 1, high: 2, exact: 3 }[c];
}

function demote(c: MatchConfidence): MatchConfidence {
  const order: MatchConfidence[] = ["low", "medium", "high", "exact"];
  return order[Math.max(0, order.indexOf(c) - 1)] ?? "low";
}

function sev(score: number | null): CveHit["severity"] {
  if (score === null || !Number.isFinite(score)) return "none";
  if (score >= 9) return "critical";
  if (score >= 7) return "high";
  if (score >= 4) return "medium";
  if (score > 0) return "low";
  return "none";
}

export { sev as severityOf };
