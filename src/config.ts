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
  /**
   * The NVD API key saved through the dashboard. `NVD_API_KEY` in the environment wins over it;
   * without either the server runs the keyless OSV-plus-cache fallback.
   */
  nvdApiKey: string | null;
  /**
   * How many product answers one `check_cves` run may refresh at NVD at most.
   *
   * Defaults above a realistic inventory (~350 programs) so a cold start with a key answers the
   * whole machine in one run — the acceptance for "complete on day one" — while later runs only
   * see the few products a scan added.
   */
  nvdProductsPerRun: number;
  /** Page cap per product query, so a huge product (Chrome) cannot turn into 60 requests. */
  nvdMaxPages: number;
  /**
   * NVD requests allowed per window in keyed mode (NVD's documented keyed window is 50 per 30 s).
   * The requests of a run are spaced to `nvdWindowMs / nvdRatePerWindow` apart instead of bursting,
   * because the live beta showed a parallel salvo eating HTTP 429 on almost every product.
   */
  nvdRatePerWindow: number;
  /** The window `nvdRatePerWindow` counts against, in milliseconds. */
  nvdWindowMs: number;
  /** Requests issued at the same time against NVD. One is the safe default; the queue honors a pause as a whole. */
  nvdConcurrency: number;
  /**
   * Extra randomised spacing per NVD request, in percent of the window interval (v0.6.5). The
   * requests of a pause that just ended would otherwise leave it as a salvo again — Cloudflare
   * in front of NVD bans exactly that shape (`error code: 1015`).
   */
  nvdJitterPct: number;
  /** Upper bound of the exponential 429 backoff in milliseconds (v0.6.5). */
  nvdBackoffCapMs: number;
  /**
   * Period of the server-side idle drain in milliseconds (v0.6.5). Between `check_cves` calls a
   * timer keeps working the open NVD queue, so a cold start finishes in minutes instead of only
   * ever advancing inside a call's time budget.
   */
  nvdIdleDrainMs: number;
  /** How many open products one idle-drain tick processes at most (v0.6.5). */
  nvdIdleDrainBatch: number;
  /**
   * Wall-clock budget of the per-product NVD walk inside one `check_cves` call. When it runs out,
   * the call returns its partial answer and the rest of the queue continues in the background, so
   * a cold keyed start never blocks long enough to trip a client-side transport timeout.
   */
  nvdCallBudgetMs: number;
  /**
   * How long a `not_found` answer (an NVD envelope that matched zero CVEs — HTTP 200 with
   * `totalResults: 0` or a 404 whose body is such an envelope) is trusted before the product is
   * asked again. Raised to 7 days in v0.6.5: the answer is a real statement about the product,
   * not a failure, and the new state tracking keeps it apart from transient errors.
   */
  nvdNotFoundTtlHours: number;
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
    nvdApiKey: null,
    nvdProductsPerRun: 400,
    nvdMaxPages: 5,
    nvdRatePerWindow: 50,
    nvdWindowMs: 30_000,
    nvdConcurrency: 1,
    nvdJitterPct: 20,
    nvdBackoffCapMs: 60_000,
    nvdIdleDrainMs: 30_000,
    nvdIdleDrainBatch: 5,
    nvdCallBudgetMs: 20_000,
    nvdNotFoundTtlHours: 168,
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
    if (typeof file.nvdApiKey === "string" && file.nvdApiKey !== "") settings.nvdApiKey = file.nvdApiKey;
    settings.nvdProductsPerRun = num(file.nvdProductsPerRun, settings.nvdProductsPerRun);
    settings.nvdMaxPages = num(file.nvdMaxPages, settings.nvdMaxPages);
    settings.nvdRatePerWindow = num(file.nvdRatePerWindow, settings.nvdRatePerWindow);
    settings.nvdWindowMs = num(file.nvdWindowMs, settings.nvdWindowMs);
    settings.nvdConcurrency = num(file.nvdConcurrency, settings.nvdConcurrency);
    settings.nvdJitterPct = num(file.nvdJitterPct, settings.nvdJitterPct);
    settings.nvdBackoffCapMs = num(file.nvdBackoffCapMs, settings.nvdBackoffCapMs);
    settings.nvdIdleDrainMs = num(file.nvdIdleDrainMs, settings.nvdIdleDrainMs);
    settings.nvdIdleDrainBatch = num(file.nvdIdleDrainBatch, settings.nvdIdleDrainBatch);
    settings.nvdCallBudgetMs = num(file.nvdCallBudgetMs, settings.nvdCallBudgetMs);
    settings.nvdNotFoundTtlHours = num(file.nvdNotFoundTtlHours, settings.nvdNotFoundTtlHours);
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
