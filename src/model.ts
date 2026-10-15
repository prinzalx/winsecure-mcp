/**
 * The domain model of the server.
 *
 * Field naming is english and locale-independent throughout, and every timestamp is an ISO-8601 UTC
 * string, because these objects are handed to a model that must be able to compare them without
 * knowing anything about the Windows display language.
 */

export type SourceKind = "registry" | "winget" | "portable";

/** One program as one source found it, before deduplication. */
export interface RawProgram {
  source: SourceKind;
  name: string;
  version: string | null;
  publisher: string | null;
  /** Registry `InstallSource`, or the winget source name. */
  install_source: string | null;
  /** winget package id, which is the strongest matching hint available. */
  package_id: string | null;
  /** Where the `.exe` lives, for the portable source. */
  path: string | null;
  /** Registry hive/key the entry came from. */
  registry_key: string | null;
  uninstall_string: string | null;
  /**
   * Set by the portable walk for a `*installer*.exe` / `*setup*.exe` file outside Program Files.
   * Such a file is archive residue (a downloaded setup sitting in a document folder), not an
   * installed program, so it never becomes a security to-do.
   */
  installer_artifact?: boolean;
}

/** One contribution to a deduplicated program. */
export interface ProgramSource {
  source: SourceKind;
  name: string;
  version: string | null;
  publisher: string | null;
  package_id: string | null;
  path: string | null;
  registry_key: string | null;
  install_source: string | null;
  uninstall_string?: string | null;
  /** See {@link RawProgram.installer_artifact}. */
  installer_artifact?: boolean;
}

/** The deduplicated program: the unit the CVE check works on. */
export interface InventoryEntry {
  id: string;
  name: string;
  version: string | null;
  publisher: string | null;
  /** Every source that reported this program. */
  sources: ProgramSource[];
  package_ids: string[];
  paths: string[];
  /** Highest-confidence match wins when a later CVE check needs one identity. */
  match_hint: string | null;
  /**
   * True when *only* installer archives reported this program. `check_cves` skips such entries:
   * an `npp.7.5.4.Installer.exe` in a document folder is not an installed program.
   */
  installer_artifact?: boolean;
  first_seen: string;
  last_seen: string;
}

export type MatchConfidence = "exact" | "high" | "medium" | "low";

export type TodoStatus = "open" | "assessed" | "dismissed";

/** A single CVE assigned to a program, with everything needed to judge it. */
export interface CveHit {
  cve_id: string;
  /** CVSS base score when the source carried one. */
  cvss: number | null;
  severity: "none" | "low" | "medium" | "high" | "critical";
  /** CISA KEV: the CVE is known to be actively exploited. */
  kev: boolean;
  kev_due_date: string | null;
  /** FIRST EPSS probability, when it was fetched. */
  epss: number | null;
  /** First version that is no longer affected, when the source data expressed it. */
  fixed_version: string | null;
  /** How the CVE was matched to this program. */
  matched_by: "cvelist_product" | "winget_id" | "osv" | "kev_product" | "manual";
  match_confidence: MatchConfidence;
  summary: string | null;
  published: string | null;
  /**
   * Set when the source carried no version range that could be checked, so the hit is only a
   * product-name match. Such a hit is listed apart from the confirmed ones and never lifts the
   * severity of its to-do.
   */
  unconfirmed?: boolean;
  /**
   * Where `cvss` came from, so a missing score is never read as "scored zero". It is only set when
   * a source really carried the score, or to mark an enrichment attempt that did not reach one
   * (`nvd_unreachable` = NVD was not reached, `nvd_no_score` = it answered without a CVSS). An unset
   * field means no source had a score, which is shown as unscored rather than `severity: "none"`.
   */
  cvss_source?: "cvelist" | "nvd" | "nvd_unreachable" | "nvd_no_score";
}

/** The effort assessment on exactly the four axes the project defined. */
export interface Assessment {
  /** (a) The replacement is a plain `.exe`/file swap. */
  exe_swap_only: boolean;
  /** (b) A new setup from the vendor is needed. */
  new_setup_needed: boolean;
  /** (c) A breaking change is expected. */
  breaking_change_expected: boolean;
  /** (d) Only part of a suite is affected; then this names it. */
  affected_part: string | null;
  reason: string;
  confidence: MatchConfidence;
  /** Who produced it, so a human can tell a model verdict from their own. */
  assessed_by: "client_sampling" | "client_saved";
  assessed_at: string;
}

/** One installed version inside a product-family to-do (see {@link Todo.versions}). */
export interface TodoVersion {
  inventory_id: string;
  program: string;
  version: string | null;
}

export interface Todo {
  id: string;
  inventory_id: string;
  program: string;
  version: string | null;
  publisher: string | null;
  cves: CveHit[];
  /**
   * CVE ids among `cves` whose version range could not be verified. They are carried along for the
   * record and listed apart in the answers, but they do not decide `max_severity` or `max_cvss`.
   */
  unconfirmed_cves: string[];
  /** Highest severity across `cves`, precomputed so `list_todos` can sort without re-deriving. */
  max_severity: "none" | "low" | "medium" | "high" | "critical";
  max_cvss: number | null;
  any_kev: boolean;
  /**
   * At least one KEV hit has a **verified** version. `list_todos` sorts on this, so an entry whose
   * only KEV signal is an unverified name match never outranks a confirmed finding.
   */
  kev_confirmed: boolean;
  /**
   * Set when several installed versions of the same product were merged into this one to-do: every
   * member version, newest first. Without it the to-do came from a single inventory entry.
   */
  versions?: TodoVersion[];
  max_epss: number | null;
  /** The newest `fixed_version` across the hits, when one is known. */
  fix_version: string | null;
  /** Weakest confidence across the confirmed hits, so an unsure match is never shown as certain. */
  match_confidence: MatchConfidence;
  /** Whether the CVE data was actually reachable when this was computed. */
  cve_status: "checked" | "unknown";
  status: TodoStatus;
  assessment: Assessment | null;
  created_at: string;
  updated_at: string;
}
