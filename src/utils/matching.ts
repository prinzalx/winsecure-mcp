/**
 * Name normalisation shared by deduplication and CVE matching.
 *
 * All of it happens server-side so a model never has to normalise strings itself, and so a German
 * "Microsoft Visual C++ 2022 Redistributable (x64) - 14.40.33810" and a plain "Microsoft Visual C++
 * 2022 Redistributable x64" land on the same key.
 */

const NOISE_WORDS = new Set([
  "version",
  "edition",
  "setup",
  "installer",
  "install",
  "plugin",
  "plugins",
  "extension",
  "extensions",
  "pack",
  "runtime",
  "runtimes",
  "tools",
  "tool",
  "engine",
  "client",
  "server",
  "component",
  "components",
  "x64",
  "x86",
  "x32",
  "64-bit",
  "32-bit",
  "64bit",
  "32bit",
  "inc",
  "llc",
  "gmbh",
  "limited",
]);

/** Collapse whitespace and drop characters that carry no matching value. */
export function squeeze(value: string): string {
  return value.replace(/\s+/g, " ").trim();
}

/**
 * The comparable form of a product name: lower-case, arch/locale markers and generic suffixes gone.
 *
 * Deliberately keeps `+` and `#` so "Notepad++" stays distinguishable, and keeps digits so
 * "Visual Studio 2022" does not collapse into "Visual Studio".
 */
export function normName(value: string | null | undefined): string {
  const s = squeeze(String(value ?? "").toLowerCase());
  return s
    .replace(/\((?:x64|x86|x32|\d+-bit|[a-z]{2}-[a-z]{2}|multi|en-us|de-de)\)/g, " ")
    .replace(/\b(version|ver\.?)\s*[:\-]?\s*[\d.]+\b/g, " ")
    .split(" ")
    .filter((w) => w !== "" && !NOISE_WORDS.has(w))
    .join(" ");
}

/**
 * Normalises a version for comparison and for the dedup key.
 *
 * The raw version is always kept for display; this only produces a comparable string, so a leading
 * `v`, a trailing build comment, or the winget range markers `<` / `>` do not fragment the inventory.
 */
export function normVersion(value: string | null | undefined): string {
  let s = String(value ?? "").trim();
  s = s.replace(/^[<>]=?\s*/, "");
  s = s.replace(/^v(?=\d)/i, "");
  s = s.replace(/\s+[-(].*$/, "");
  return squeeze(s);
}

/** The key that unifies the same program found by several sources. */
export function dedupKey(name: string | null | undefined, version: string | null | undefined): string {
  return `${normName(name)}|${normVersion(version)}`;
}

/**
 * Compares dotted numeric versions segment by segment.
 *
 * Returns a negative number when `a < b`. Non-numeric segments compare as text, which is enough for
 * the range checks here (the CVE data itself carries the authoritative ranges).
 */
export function compareVersions(a: string, b: string): number {
  const pa = normVersion(a).split(".");
  const pb = normVersion(b).split(".");
  const len = Math.max(pa.length, pb.length);
  for (let i = 0; i < len; i += 1) {
    const sa = pa[i] ?? "0";
    const sb = pb[i] ?? "0";
    const na = Number.parseInt(sa, 10);
    const nb = Number.parseInt(sb, 10);
    const both = Number.isFinite(na) && Number.isFinite(nb);
    if (both && na !== nb) return na < nb ? -1 : 1;
    if (!both && sa !== sb) return sa < sb ? -1 : 1;
  }
  return 0;
}

/** 0..1 similarity of two names, used to decide `match_confidence`. */
export function similarity(a: string, b: string): number {
  const x = normName(a).replace(/\s/g, "");
  const y = normName(b).replace(/\s/g, "");
  if (x === "" || y === "") return 0;
  if (x === y) return 1;
  const dist = levenshtein(x, y);
  return 1 - dist / Math.max(x.length, y.length);
}

function levenshtein(a: string, b: string): number {
  const m = a.length;
  const n = b.length;
  if (m === 0) return n;
  if (n === 0) return m;

  let prev: number[] = Array.from({ length: n + 1 }, (_, j) => j);
  for (let i = 1; i <= m; i += 1) {
    const curr: number[] = [i];
    for (let j = 1; j <= n; j += 1) {
      const cost = a[i - 1] === b[j - 1] ? 0 : 1;
      curr[j] = Math.min((curr[j - 1] ?? 0) + 1, (prev[j] ?? 0) + 1, prev[j - 1] ?? 0);
    }
    prev = curr;
  }
  return prev[n] ?? 0;
}

/**
 * Maps a numeric severity band. The number is locale-independent, the label is always english, and
 * the display text that Windows would show stays out of the comparison entirely.
 */
export function severityBand(score: number | null | undefined): "none" | "low" | "medium" | "high" | "critical" {
  if (score === null || score === undefined || !Number.isFinite(score)) return "none";
  if (score >= 9) return "critical";
  if (score >= 7) return "high";
  if (score >= 4) return "medium";
  if (score > 0) return "low";
  return "none";
}
