import { mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { homedir } from "node:os";
import { dirname, join } from "node:path";

/**
 * Reads `--flag value` and bare `--flag` from the command line. Command line wins over the
 * environment, because an explicit invocation is the stronger signal.
 */
export function parseArgs(argv: readonly string[]): Map<string, string | boolean> {
  const flags = new Map<string, string | boolean>();
  for (let i = 0; i < argv.length; i += 1) {
    const arg = argv[i] ?? "";
    if (!arg.startsWith("--")) {
      continue;
    }
    const name = arg.slice(2);
    const next = argv[i + 1];
    if (next !== undefined && !next.startsWith("--")) {
      flags.set(name, next);
      i += 1;
    } else {
      flags.set(name, true);
    }
  }
  return flags;
}

export const ARGS = parseArgs(process.argv.slice(2));

/**
 * Server settings. Every value has a working default, so a missing config file is not an error:
 * the server runs with the defaults and writes them out on first save.
 */
export interface Settings {
  /** Directory for the ToDo list, the caches and the config itself. */
  dataDir: string;
  /** TTL of the CISA KEV feed on disk. */
  kevTtlHours: number;
  /** TTL of the cvelistV5 delta on disk. */
  cvelistTtlHours: number;
  /** TTL of an EPSS answer on disk. */
  epssTtlHours: number;
  /** Root paths never walked by the portable-app scan. */
  portableExcludes: string[];
  /** Maximum portable `.exe` hits kept before the result is cut (the paths are still reported). */
  portableMaxResults: number;
  /** Timeout of the portable scan in milliseconds. */
  portableTimeoutMs: number;
  /** Timeout of a single outbound request in milliseconds. */
  httpTimeoutMs: number;
}

export interface ConfigStore {
  readonly settings: Settings;
  readonly path: string;
  save(): void;
}

const DEFAULT_EXCLUDES = [
  "C:\\Windows",
  "C:\\WinSxS",
  "node_modules",
  "$Recycle.Bin",
  "C:\\$Recycle.Bin",
  "AppData\\Local\\Temp",
  "Temp",
];

function dataDirDefault(): string {
  const cli = ARGS.get("data-dir");
  if (typeof cli === "string" && cli !== "") {
    return cli;
  }
  const env = process.env.WSMD_DATA_DIR;
  if (env) {
    return env;
  }
  const base = process.env.APPDATA ?? join(homedir(), ".winsecure-mcp");
  return join(base, "winsecure-mcp");
}

function configPathDefault(): string {
  const cli = ARGS.get("config");
  if (typeof cli === "string" && cli !== "") {
    return cli;
  }
  const env = process.env.WSMD_CONFIG;
  if (env) {
    return env;
  }
  return join(dataDirDefault(), "config.json");
}

function num(value: unknown, fallback: number): number {
  return typeof value === "number" && Number.isFinite(value) && value > 0 ? value : fallback;
}

export function loadConfig(): ConfigStore {
  const path = configPathDefault();
  const dir = dataDirDefault();

  const settings: Settings = {
    dataDir: dir,
    kevTtlHours: 24,
    cvelistTtlHours: 24,
    epssTtlHours: 24,
    portableExcludes: [...DEFAULT_EXCLUDES],
    portableMaxResults: 40,
    portableTimeoutMs: 60_000,
    httpTimeoutMs: 15_000,
  };

  let raw: unknown;
  try {
    raw = JSON.parse(readFileSync(path, "utf8"));
  } catch {
    raw = undefined;
  }

  if (raw && typeof raw === "object") {
    const file = raw as Partial<Settings>;
    if (typeof file.dataDir === "string" && file.dataDir !== "") settings.dataDir = file.dataDir;
    settings.kevTtlHours = num(file.kevTtlHours, settings.kevTtlHours);
    settings.cvelistTtlHours = num(file.cvelistTtlHours, settings.cvelistTtlHours);
    settings.epssTtlHours = num(file.epssTtlHours, settings.epssTtlHours);
    if (Array.isArray(file.portableExcludes)) settings.portableExcludes = file.portableExcludes.map(String);
    settings.portableMaxResults = num(file.portableMaxResults, settings.portableMaxResults);
    settings.portableTimeoutMs = num(file.portableTimeoutMs, settings.portableTimeoutMs);
    settings.httpTimeoutMs = num(file.httpTimeoutMs, settings.httpTimeoutMs);
  }

  try {
    mkdirSync(settings.dataDir, { recursive: true });
  } catch {
    // The data directory may already exist or be created lazily by the first save.
  }

  return {
    settings,
    path,
    save() {
      try {
        mkdirSync(dirname(path), { recursive: true });
        writeFileSync(path, `${JSON.stringify(settings, null, 2)}\n`, "utf8");
      } catch {
        // A read-only profile must not break the server.
      }
    },
  };
}
