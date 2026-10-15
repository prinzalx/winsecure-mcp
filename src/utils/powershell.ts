import { execFile } from "node:child_process";
import { promisify } from "node:util";

const execFileAsync = promisify(execFile);

const POWERSHELL = "powershell.exe";

/**
 * Flags every invocation shares. `-NoProfile` keeps startup fast and independent of whatever the
 * interactive user put in their profile.
 */
const BASE_ARGS = ["-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass"] as const;

/**
 * Forces UTF-8 so non-ASCII program names survive the pipe, and turns non-terminating errors into
 * terminating ones so a failing cmdlet actually produces a non-zero exit code.
 */
const PRELUDE =
  "$OutputEncoding = [System.Text.Encoding]::UTF8; " +
  "[Console]::OutputEncoding = [System.Text.Encoding]::UTF8; " +
  "$ErrorActionPreference = 'Stop';";

const MAX_BUFFER = 32 * 1024 * 1024;

export interface PowerShellOptions {
  /** Milliseconds before the process is killed. */
  timeoutMs?: number;
  /** Wrap the command so its output is returned as JSON. Defaults to `true`. */
  json?: boolean;
  /** `ConvertTo-Json -Depth` value. Defaults to 5. */
  depth?: number;
}

export interface PowerShellResult<T = unknown> {
  ok: boolean;
  /** Parsed `ConvertTo-Json` output, or `null` when there was no output. */
  data: T | null;
  exitCode: number | null;
  stdout: string;
  stderr: string;
  durationMs: number;
  error?: string;
}

/**
 * Quotes a value for embedding in a PowerShell single-quoted string literal.
 *
 * Single-quoted literals do not interpolate, which makes injection via `$` or backticks
 * impossible; the only character that needs doubling is the quote itself.
 */
export function psQuote(value: string | number | boolean | null | undefined): string {
  if (value === null || value === undefined || value === "") {
    return "''";
  }
  return `'${String(value).replace(/'/g, "''")}'`;
}

function parseOutput(stdout: string): unknown | undefined {
  const trimmed = stdout.trim();
  if (trimmed === "") {
    return null;
  }
  try {
    return JSON.parse(trimmed);
  } catch {
    return undefined;
  }
}

/**
 * Runs a PowerShell command and returns its output.
 *
 * The `command` runs inside `& { ... }`, so it may contain several statements as long as the last
 * one emits the pipeline that should be captured.
 */
export async function runPowerShell<T = unknown>(
  command: string,
  options: PowerShellOptions = {},
): Promise<PowerShellResult<T>> {
  const json = options.json ?? true;
  const depth = options.depth ?? 5;
  const timeoutMs = options.timeoutMs ?? 30_000;
  const body = command.trim();

  const script = json
    ? `${PRELUDE}\n& { ${body} } | ConvertTo-Json -Depth ${depth} -Compress`
    : `${PRELUDE}\n${body}`;

  const startedAt = Date.now();

  try {
    const { stdout, stderr } = await execFileAsync(POWERSHELL, [...BASE_ARGS, script], {
      timeout: timeoutMs,
      maxBuffer: MAX_BUFFER,
      windowsHide: true,
      encoding: "utf8",
    });

    const parsed = json ? parseOutput(stdout) : undefined;
    if (json) {
      if (parsed === undefined && stdout.trim() !== "") {
        return {
          ok: false,
          data: null,
          exitCode: 0,
          stdout,
          stderr,
          durationMs: Date.now() - startedAt,
          error: "PowerShell returned output that is not valid JSON",
        };
      }
      return {
        ok: true,
        data: (parsed ?? null) as T | null,
        exitCode: 0,
        stdout,
        stderr,
        durationMs: Date.now() - startedAt,
      };
    }

    return { ok: true, data: null, exitCode: 0, stdout, stderr, durationMs: Date.now() - startedAt };
  } catch (cause) {
    const err = cause as NodeJS.ErrnoException & {
      code?: number | string;
      killed?: boolean;
      stdout?: string;
      stderr?: string;
    };

    const stdout = err.stdout ?? "";
    const stderr = err.stderr ?? "";
    const timedOut = Boolean(err.killed) || err.code === "ETIMEDOUT";

    // A missing powershell.exe (WSL without the interpreter, a minimal container) produces exactly
    // the empty stdout/stderr the "no rows" branch below would happily read as success. Reported as
    // an error here, so a scan says "I cannot see Windows" instead of "0 programs".
    if (err.code === "ENOENT") {
      return {
        ok: false,
        data: null,
        exitCode: null,
        stdout,
        stderr,
        durationMs: Date.now() - startedAt,
        error: `${POWERSHELL} not found — this host does not offer Windows PowerShell`,
      };
    }

    // A cmdlet whose errors were suppressed still leaves `$?` false, which makes powershell.exe
    // exit non-zero even though the query simply came back empty. Empty output and empty stderr is
    // therefore the "no rows" case, not a failure.
    if (!timedOut && stderr.trim() === "" && stdout.trim() === "") {
      return {
        ok: true,
        data: null,
        exitCode: typeof err.code === "number" ? err.code : null,
        stdout: "",
        stderr,
        durationMs: Date.now() - startedAt,
      };
    }

    let message: string;
    if (timedOut) {
      message = `PowerShell timed out after ${String(timeoutMs)} ms`;
    } else if (stderr.trim() !== "") {
      message = stderr.trim().split("\n")[0] ?? "PowerShell failed";
    } else {
      message = `PowerShell exited with code ${String(err.code ?? "unknown")}`;
    }

    return {
      ok: false,
      data: null,
      exitCode: typeof err.code === "number" ? err.code : null,
      stdout,
      stderr,
      durationMs: Date.now() - startedAt,
      error: message,
    };
  }
}

/**
 * Normalises `ConvertTo-Json` output, which is a bare object for a single result.
 *
 * The input is `unknown` on purpose: everything coming out of PowerShell has to be treated as
 * untrusted shape, and the callers narrow the elements themselves.
 */
export function asArray<T = unknown>(data: unknown): T[] {
  if (data === null || data === undefined) {
    return [];
  }
  return (Array.isArray(data) ? data : [data]) as T[];
}
