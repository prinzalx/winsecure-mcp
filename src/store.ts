import { existsSync, mkdirSync, readFileSync, renameSync, writeFileSync } from "node:fs";
import { dirname, join } from "node:path";

import type { InventoryEntry, Todo } from "./model.js";

export interface TodoFile {
  /** Schema marker, so a later version can migrate instead of failing. */
  schema: number;
  updated_at: string;
  inventory: InventoryEntry[];
  todos: Todo[];
  /**
   * The lookup mode (`nvd-keyed` / `keyless-osv+cached`) the newest `check_cves` ran in, so
   * `list_todos` and the dashboard can tell a thin keyless answer from a clean machine even after
   * the tool call that produced it is long gone.
   */
  cve_mode?: string | null;
}

export interface DataStore {
  readonly dir: string;
  readonly path: string;
  load(): TodoFile;
  save(data: TodoFile): void;
}

const EMPTY: TodoFile = { schema: 1, updated_at: new Date(0).toISOString(), inventory: [], todos: [] };

/**
 * One JSON file holds inventory and ToDo list together.
 *
 * A single file is deliberate: the two are always read together by `list_todos`, and the only writer
 * is the server itself, so there is no concurrent writer to coordinate. The write goes to a sibling
 * temp file and is renamed, so a crash mid-write cannot leave a half-readable store behind.
 */
export function openStore(dir: string): DataStore {
  const path = join(dir, "winsecure.json");

  return {
    dir,
    path,
    load() {
      try {
        const raw = JSON.parse(readFileSync(path, "utf8")) as Partial<TodoFile>;
        return {
          schema: 1,
          updated_at: typeof raw.updated_at === "string" ? raw.updated_at : new Date(0).toISOString(),
          inventory: Array.isArray(raw.inventory) ? (raw.inventory as InventoryEntry[]) : [],
          todos: Array.isArray(raw.todos) ? (raw.todos as Todo[]) : [],
          cve_mode: typeof raw.cve_mode === "string" ? raw.cve_mode : null,
        };
      } catch {
        return { ...EMPTY, inventory: [], todos: [] };
      }
    },
    save(data) {
      try {
        mkdirSync(dirname(path), { recursive: true });
        const tmp = `${path}.tmp`;
        writeFileSync(tmp, `${JSON.stringify(data, null, 2)}\n`, "utf8");
        renameSync(tmp, path);
      } catch {
        // A read-only data directory must not break a read-only call.
      }
    },
  };
}

/** Whether a store file exists at all, which decides the "run scan_inventory first" hint. */
export function storeExists(store: DataStore): boolean {
  return existsSync(store.path);
}
