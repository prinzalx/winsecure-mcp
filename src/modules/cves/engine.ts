import { compareVersions, normName, normVersion, squeeze } from "../../utils/matching.js";
import type { ProductIndex, KevIndex, CveRecord, KevEntry } from "./feeds.js";
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
 * The cold-start plausibility verdict for a name-only match.
 *
 * A thin local delta index carries no range data for old CVEs (the delta only ever accumulates
 * recent ones), so the range check cannot rule them out and a KEV name match alone would headline
 * a 2016 EdgeHTML bug against Edge 155. The rule: the **era** of an installed version — the larger
 * of its first two numeric segments, since product schemes encode the age in the major (Edge 155,
 * 7-Zip 26) or the minor (Git 2.55, WhatsApp 2.2639) — must not sit clearly above the CVE's
 * publication year. The *era* of a version is the larger of its first two numeric segments, because
 * product schemes hide their age in either one: Edge 155 and 7-Zip 26 in the major, Git 2.55 and
 * WhatsApp 2.2639 in the minor. `slack` of 25 tolerates the fastest common scheme before the pair
 * counts as impossible: Edge 155 vs. a 2016 CVE, WhatsApp 2.2639 vs. 2019 and Git 2.55 vs. a 2025
 * CVE drop, while 7-Zip 26.02 vs. a 2025 CVE stays plausibly kept (its real exclusion — affected is
 * < 24.07 — comes with the range as soon as the delta index carries that CVE).
 *
 * The bias is deliberate and bounded: it only ever **drops a name-only match no range confirmed**,
 * never creates a hit, and it never applies when a comparable range already decided the question.
 * A product with a naturally high version number can lose an unconfirmed hit this way; the live
 * beta showed the opposite error (old CVEs headlining) was the one users complained about.
 */
export function eraImplausible(installed: string | null, published: string | null): boolean {
  if (!installed || !published) return false;
  const year = Number.parseInt(published.slice(0, 4), 10);
  // Only the modern era is judged; a CVE before 2000 has no comparable year scale here.
  if (!Number.isFinite(year) || year < 2000) return false;
  const parts = normVersion(installed).split(".");
  const era = Math.max(Number.parseInt(parts[0] ?? "", 10) || 0, Number.parseInt(parts[1] ?? "", 10) || 0);
  if (!Number.isFinite(era) || era === 0) return false;
  const SLACK = 25;
  return era > (year % 100) + SLACK;
}

/**
 * The CVE hits for one program, from the local product index plus the KEV overlay.
 *
 * `checked` says whether real CVE data was available at all. When it was not, the caller marks the
 * todo `cve_status: "unknown"` instead of reporting an empty hit list as "no vulnerabilities".
 * `dropped` counts the name matches the version verdict rejected — a known affected range that
 * excludes the installed version, or the era heuristic for a match no range can confirm.
 */
export function matchProgram(
  entry: InventoryEntry,
  index: ProductIndex,
  kev: KevIndex,
): { hits: CveHit[]; dropped: number; checked: boolean; data_from: string } {
  const checked = index.byProduct.size > 0 || kev.byCve.size > 0;
  if (!checked) return { hits: [], dropped: 0, checked: false, data_from: "none" };

  const byId = new Map<string, CveHit>();
  // Counted once per CVE id: the product loop and the KEV overlay can both reject the same pair.
  const droppedIds = new Set<string>();

  for (const cand of candidates(entry)) {
    const records = index.byProduct.get(normName(cand.name)) ?? [];
    for (const rec of records) {
      const verdict = versionAffected(entry.version, rec);
      if (!verdict.affected) {
        droppedIds.add(rec.cve_id);
        continue;
      }
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
    if (verdict && !verdict.affected) {
      droppedIds.add(kevEntry.cve_id);
      continue;
    }

    // No record, or bounds that cannot be compared: the version was not verified. Before such a
    // name-only match is kept, the era heuristic gets its chance to drop the obviously impossible
    // pairs (a 2016 CVE against Edge 155), which is what carries the verdict in the cold-start phase
    // where the thin delta index never learned a range for the old CVE at all.
    if (verdict === null && eraImplausible(entry.version, detail?.published ?? kevPublishedHint(kevEntry))) {
      droppedIds.add(kevEntry.cve_id);
      continue;
    }

    // Bounds that could not be compared keep the hit but never call it verified, so it is reported
    // apart instead of lifting the severity of the whole to-do.
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

  return { hits: [...byId.values()], dropped: droppedIds.size, checked, data_from: index.from !== "none" ? index.from : kev.from };
}

/**
 * The KEV feed carries no publication date, so the era hint falls back to the CVE id's year, which
 * is when the vulnerability was assigned — close enough for a plausibility check and nothing more.
 */
function kevPublishedHint(entry: KevEntry): string | null {
  const year = /^(?:CVE-)?(\d{4})-/i.exec(entry.cve_id)?.[1];
  return year ? `${year}-01-01` : null;
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
