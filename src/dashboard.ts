import type { TodoFile } from "./store.js";
import type { ToolDefinition } from "./types.js";
import type { Todo } from "./model.js";
import { compareTodoRank } from "./modules/todos/todo.js";
import type { TodoVersion } from "./model.js";

/**
 * One remembered tool call.
 *
 * The dashboard is a read view onto the same process, so the activity log lives in memory: after a
 * restart it is empty again, which is honest, and nothing has to be written to disk on every call.
 */
export interface ActivityEntry {
  at: string;
  tool: string;
  ok: boolean;
  duration_ms: number;
  /** Where the call came from: `stdio` or `web`. */
  origin: string;
  summary: string;
}

export interface Activity {
  add(entry: ActivityEntry): void;
  recent(limit?: number): ActivityEntry[];
}

/** A ring buffer of the newest calls, newest first. */
export function createActivity(capacity = 50): Activity {
  const entries: ActivityEntry[] = [];
  return {
    add(entry) {
      entries.unshift(entry);
      if (entries.length > capacity) entries.length = capacity;
    },
    recent(limit = 20) {
      return entries.slice(0, limit);
    },
  };
}

const SEVERITIES = ["critical", "high", "medium", "low", "none"] as const;

export interface DashboardState {
  version: string;
  server_time: string;
  data_dir: string;
  store_path: string;
  store_exists: boolean;
  /** Sampling support of the stdio client currently attached, or null before the handshake. */
  client_sampling: boolean | null;
  inventory: {
    programs: number;
    scanned_at: string | null;
    /** How many entries each source reported at least once. */
    per_source: Record<string, number>;
    with_package_id: number;
    with_path: number;
  };
  todos: {
    total: number;
    open: number;
    assessed: number;
    dismissed: number;
    kev: number;
    /** Active entries that carry at least one hit whose version could not be verified. */
    with_unconfirmed: number;
    by_severity: Record<(typeof SEVERITIES)[number], number>;
    with_epss: number;
    assessed_share: number | null;
    top: DashboardTodoRow[];
  };
  tools: { name: string; module: string; title: string; description: string; docs: string }[];
  activity: ActivityEntry[];
}

/** The trimmed todo row the dashboard renders; the full CVE list would be too much for the card. */
export interface DashboardTodoRow {
  id: string;
  program: string;
  version: string | null;
  cve_count: number;
  /** CVE ids carried for the record whose version could not be verified. */
  unconfirmed_count: number;
  /** Every installed version merged into this row, newest first (a product-family to-do). */
  versions: TodoVersion[] | null;
  max_severity: Todo["max_severity"];
  max_cvss: number | null;
  max_epss: number | null;
  any_kev: boolean;
  match_confidence: Todo["match_confidence"];
  cve_status: Todo["cve_status"];
  status: Todo["status"];
  fix_version: string | null;
  assessed_by: string | null;
  updated_at: string;
}

function todoRow(t: Todo): DashboardTodoRow {
  return {
    id: t.id,
    program: t.program,
    version: t.version,
    cve_count: t.cves.length,
    unconfirmed_count: t.unconfirmed_cves?.length ?? 0,
    versions: t.versions?.length ? t.versions : null,
    max_severity: t.max_severity,
    max_cvss: t.max_cvss,
    max_epss: t.max_epss,
    any_kev: t.any_kev,
    match_confidence: t.match_confidence,
    cve_status: t.cve_status,
    status: t.status,
    fix_version: t.fix_version,
    assessed_by: t.assessment?.assessed_by ?? null,
    updated_at: t.updated_at,
  };
}

/**
 * The numbers the dashboard shows, computed straight from the store.
 *
 * Reading is done through the same store every tool uses, so the web view can never disagree with
 * what a tool call returned.
 */
export function computeState(options: {
  version: string;
  store: TodoFile;
  storeExists: boolean;
  dataDir: string;
  storePath: string;
  tools: ToolDefinition[];
  activity: ActivityEntry[];
  clientSampling: boolean | null;
}): DashboardState {
  const { store } = options;

  const perSource: Record<string, number> = { registry: 0, winget: 0, portable: 0 };
  let withPackageId = 0;
  let withPath = 0;
  let lastScan: string | null = null;
  for (const e of store.inventory) {
    for (const s of new Set(e.sources.map((x) => x.source))) perSource[s] = (perSource[s] ?? 0) + 1;
    if (e.package_ids.length > 0) withPackageId += 1;
    if (e.paths.length > 0) withPath += 1;
    // The newest last_seen is the actual scan time; store.updated_at also moves when a todo is
    // assessed, which would make the card lie about when the machine was read.
    if (e.last_seen > (lastScan ?? "")) lastScan = e.last_seen;
  }

  const active = store.todos.filter((t) => t.status !== "dismissed");
  const bySeverity = { critical: 0, high: 0, medium: 0, low: 0, none: 0 };
  let kev = 0;
  let withEpss = 0;
  let withUnconfirmed = 0;
  for (const t of active) {
    bySeverity[t.max_severity] = (bySeverity[t.max_severity] ?? 0) + 1;
    if (t.any_kev) kev += 1;
    if (t.max_epss !== null) withEpss += 1;
    if ((t.unconfirmed_cves?.length ?? 0) > 0) withUnconfirmed += 1;
  }

  // Same order list_todos uses, so the dashboard cards and the tool answer agree.
  const top = [...active].sort(compareTodoRank).slice(0, 10)
    .map(todoRow);

  return {
    version: options.version,
    server_time: new Date().toISOString(),
    data_dir: options.dataDir,
    store_path: options.storePath,
    store_exists: options.storeExists,
    client_sampling: options.clientSampling,
    inventory: {
      programs: store.inventory.length,
      scanned_at: lastScan,
      per_source: perSource,
      with_package_id: withPackageId,
      with_path: withPath,
    },
    todos: {
      total: store.todos.length,
      open: store.todos.filter((t) => t.status === "open").length,
      assessed: store.todos.filter((t) => t.status === "assessed").length,
      dismissed: store.todos.filter((t) => t.status === "dismissed").length,
      kev,
      with_unconfirmed: withUnconfirmed,
      by_severity: bySeverity,
      with_epss: withEpss,
      assessed_share: active.length === 0 ? null : Math.round((store.todos.filter((t) => t.status === "assessed").length / active.length) * 100),
      top,
    },
    tools: options.tools.map((t) => ({
      name: t.name,
      module: t.module,
      title: t.title,
      description: t.description,
      docs: t.docs ?? "",
    })),
    activity: options.activity,
  };
}
