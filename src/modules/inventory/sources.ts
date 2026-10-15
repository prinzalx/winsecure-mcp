import { spawnSync } from "node:child_process";

import { asArray, psQuote, runPowerShell } from "../../utils/powershell.js";
import { normVersion, squeeze } from "../../utils/matching.js";
import type { RawProgram } from "../../model.js";

/**
 * The four Uninstall locations of §3.1.
 *
 * Both hives and both WOW6432Node views are needed: a 32-bit program on a 64-bit system writes to
 * the WOW key, and a per-user install appears only under HKCU.
 */
const UNINSTALL_KEYS = [
  { path: "HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall", hive: "HKLM", bits: "64" },
  { path: "HKLM:\\SOFTWARE\\WOW6432Node\\Microsoft\\Windows\\CurrentVersion\\Uninstall", hive: "HKLM", bits: "32" },
  { path: "HKCU:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall", hive: "HKCU", bits: "64" },
  { path: "HKCU:\\SOFTWARE\\WOW6432Node\\Microsoft\\Windows\\CurrentVersion\\Uninstall", hive: "HKCU", bits: "32" },
] as const;

/**
 * Reading the registry rather than `Get-Package` keeps the output locale-independent: the field
 * names are the registry value names, which are the same on every Windows language.
 *
 * Access denied on a key is skipped in the script and shows up as a missing row, not as an error.
 */
export async function readRegistryPrograms(timeoutMs = 60_000): Promise<{ programs: RawProgram[]; error?: string }> {
  const paths = UNINSTALL_KEYS.map((k) => psQuote(k.path)).join(",");

  const script =
    "$ErrorActionPreference='SilentlyContinue'; " +
    `$roots = @(${paths}); ` +
    "$out = @(); " +
    "foreach ($r in $roots) { " +
    "  Get-ChildItem -LiteralPath $r -ErrorAction SilentlyContinue | ForEach-Object { " +
    "    $p = $null; try { $p = Get-ItemProperty -LiteralPath $_.PSPath -ErrorAction Stop } catch { }; " +
    "    if ($null -ne $p -and $p.DisplayName) { " +
    "      $out += [pscustomobject]@{ " +
    "        Name=[string]$p.DisplayName; Version=[string]$p.DisplayVersion; Publisher=[string]$p.Publisher; " +
    "        InstallSource=[string]$p.InstallSource; UninstallString=[string]$p.UninstallString; Key=[string]$_.PSPath } } } }; " +
    "$out";

  const res = await runPowerShell<Record<string, unknown>>(script, { timeoutMs, depth: 3 });
  if (!res.ok) {
    return { programs: [], error: res.error ?? "registry read failed" };
  }

  const programs: RawProgram[] = [];
  for (const row of asArray<Record<string, unknown>>(res.data)) {
    const name = String(row.Name ?? "").trim();
    if (name === "") continue;
    const key = String(row.Key ?? "");
    const bits = key.includes("WOW6432Node") ? "32" : "64";
    const hive = key.startsWith("HKEY_CURRENT_USER") ? "HKCU" : "HKLM";
    programs.push({
      source: "registry",
      name,
      version: normVersion(String(row.Version ?? "")) || null,
      publisher: String(row.Publisher ?? "").trim() || null,
      install_source: String(row.InstallSource ?? "").trim() || null,
      package_id: packageIdFromKey(key),
      path: null,
      registry_key: `${hive}\\${bits}\\${leafOf(key)}`,
      uninstall_string: String(row.UninstallString ?? "").trim() || null,
    });
  }

  // Reading all four Uninstall keys without a single DisplayName is not a plausible result on a
  // working Windows host; it means the process could not see the registry at all. Saying so keeps a
  // silent failure from looking like a clean "0 programs".
  if (programs.length === 0) {
    return { programs, error: "no DisplayName entries found under the four Uninstall keys" };
  }
  return { programs };
}

/**
 * The key name is usually the product name or a GUID.
 *
 * Only the `<id>_Microsoft.Winget.Source_8wekyb3d8bbwe` shape carries a real winget package id; a
 * GUID key carries none, and inventing one from a GUID would produce matches that mean nothing.
 */
function packageIdFromKey(key: string): string | null {
  const leaf = leafOf(key);
  const match = /^(.+?)_Microsoft\.Winget\.Source_[A-Za-z0-9]+$/.exec(leaf);
  return match?.[1] ?? null;
}

function leafOf(key: string): string {
  const parts = key.split("\\").filter(Boolean);
  return parts[parts.length - 1] ?? key;
}

/**
 * `winget list` for Store- and winget-managed apps.
 *
 * winget 1.29 has no JSON output for `list`, and its table headers are localised
 * ("Name", "Version" stay; the separator row is always dashes). Parsing on the separator row and
 * then splitting on runs of two or more spaces keeps this working regardless of the display
 * language, because the column *positions* are stable even when the header words are not.
 */
export async function readWingetPrograms(timeoutMs = 180_000): Promise<{ programs: RawProgram[]; error?: string; rawLines: number }> {
  const { execFile } = await import("node:child_process");
  const { promisify } = await import("node:util");

  const run = promisify(execFile);
  let stdout = "";
  try {
    const res = await run("winget.exe", ["list", "--accept-source-agreements", "--disable-interactivity"], {
      timeout: timeoutMs,
      maxBuffer: 16 * 1024 * 1024,
      windowsHide: true,
      encoding: "utf8",
    });
    stdout = res.stdout;
  } catch (cause) {
    const err = cause as { killed?: boolean; code?: number | string; message?: string };
    const message = err.killed ? `winget list timed out after ${String(timeoutMs)} ms` : (err.message ?? "winget list failed");
    return { programs: [], error: message, rawLines: 0 };
  }

  const lines = stdout.split(/\r?\n/).map((l) => l.replace(/\uFEFF/g, ""));
  const sep = lines.findIndex((l) => /^[-\s]{20,}$/.test(l));
  if (sep < 0) {
    return { programs: [], error: "winget list output had no table separator row", rawLines: lines.length };
  }

  const programs: RawProgram[] = [];
  for (const line of lines.slice(sep + 1)) {
    if (line.trim() === "") continue;
    const cols = line.split(/\s{2,}/).map((c) => squeeze(c));
    if (cols.length < 2) continue;
    const name = cols[0] ?? "";
    const id = cols[1] ?? "";
    const version = cols[2] ?? "";
    const source = cols[cols.length - 1] ?? "";
    if (name === "" || id === "") continue;

    // The trailing columns shift when there is no upgrade available, so the source is only trusted
    // when it is in the last position of a five-column row.
    const isWingetManaged = cols.length >= 5 && ["winget", "msstore"].includes(String(source ?? "").toLowerCase());
    const pkgId = isWingetManaged || isPackageId(String(id)) ? String(id) : null;

    programs.push({
      source: "winget",
      name: String(name),
      version: normVersion(String(version ?? "")) || null,
      publisher: null,
      install_source: isWingetManaged ? String(source) : null,
      package_id: pkgId,
      path: null,
      registry_key: null,
      uninstall_string: null,
    });
  }
  return { programs, rawLines: lines.length };
}

/** A winget package id looks like `Vendor.Product`; an `ARP\...` or `MSIX\...` id is a fallback key, not a package id. */
function isPackageId(id: string): boolean {
  if (/^(ARP|MSIX)\\/i.test(id)) return false;
  return /^[A-Za-z0-9]+([._-][A-Za-z0-9]+)+$/.test(id);
}

/**
 * Whether the two interpreters the Windows sources need can actually be started.
 *
 * This answers the question a scan cannot: on a machine where the server runs as a Linux process
 * (the stdio child inside WSL) every Windows source comes back empty, and the reason is the missing
 * interpreter, not an empty registry. Reported next to the counters instead of "0 programs".
 */
export function probeCommands(): { powershell: boolean; winget: boolean; finder: string } {
  // `where.exe` is part of Windows; WSL and a minimal container get `which`. Both are only asked
  // whether a name resolves, so nothing is executed.
  const finder = process.platform === "win32" ? "where.exe" : "which";
  const found = (cmd: string): boolean => {
    try {
      const res = spawnSync(finder, [cmd], { timeout: 5_000, encoding: "utf8" });
      return res.status === 0;
    } catch {
      return false;
    }
  };
  return { powershell: found("powershell.exe"), winget: found("winget.exe"), finder };
}

/**
 * Filesystem walk for portable `.exe` files with version information.
 *
 * Everything about the walk happens in PowerShell so the exclusions apply before the expensive
 * part (reading version info). Access-denied directories are skipped, which is the normal case and
 * never an error.
 */
export async function findPortablePrograms(options: {
  roots: string[];
  excludes: string[];
  maxResults: number;
  timeoutMs: number;
}): Promise<{ programs: RawProgram[]; scanned: number; skipped_paths: string[]; timedOut: boolean; error?: string }> {
  // A JSON array is not a PowerShell array literal, so it travels as a quoted string and is parsed
  // by ConvertFrom-Json.
  const rootsJson = psQuote(JSON.stringify(options.roots));
  const excludesJson = psQuote(JSON.stringify(options.excludes));

  const script =
    "$ErrorActionPreference='SilentlyContinue'; " +
    `$roots = ${rootsJson} | ConvertFrom-Json; $excludes = ${excludesJson} | ConvertFrom-Json; ` +
    "$limit = " + String(Math.max(1, options.maxResults)) + "; " +
    "$sw = [System.Diagnostics.Stopwatch]::StartNew(); " +
    "$budgetMs = " + String(Math.max(1000, options.timeoutMs - 2000)) + "; " +
    "$found = @(); $scanned = 0; $skipped = @{}; " +
    "$excludes = @($excludes | Where-Object { $_ }); " +
    'function Test-Excluded($p) { foreach ($x in $excludes) { if ($x -match "[\\/]") { if ($p -like ("*" + $x + "*")) { return $true } } else { foreach ($seg in ($p -split "[\\/]")) { if ($seg -eq $x) { return $true } } } }; return $false }; ' +
    "$stack = New-Object System.Collections.Generic.Stack[string]; " +
    "foreach ($r in $roots) { if (Test-Path -LiteralPath $r) { $stack.Push($r) } }; " +
    "while ($stack.Count -gt 0) { " +
    "  $dir = $stack.Pop(); " +
    "  if ($sw.ElapsedMilliseconds -gt $budgetMs) { break }; " +
    "  $skip = $false; " +
    "  if (Test-Excluded $dir) { $skip = $true }; " +
    "  if ($skip) { $skipped[$dir] = 1; continue }; " +
    "  $files = $null; try { $files = @(Get-ChildItem -LiteralPath $dir -Filter *.exe -File -ErrorAction SilentlyContinue) } catch { }; " +
    "  if ($found.Count -ge $limit) { break }; " +
    "  foreach ($f in $files) { " +
    "    $scanned = $scanned + 1; " +
    "    $vi = $f.VersionInfo; " +
    "    if ($null -ne $vi -and $vi.ProductName) { " +
    "      $found += [pscustomobject]@{ File=$f.FullName; Product=[string]$vi.ProductName; " +
    "        ProductVersion=[string]$vi.ProductVersion; Company=[string]$vi.CompanyName } } }; " +
    "  foreach ($d in @(Get-ChildItem -LiteralPath $dir -Directory -ErrorAction SilentlyContinue)) { $stack.Push($d.FullName) } }; " +
    "@{ Found=$found; Scanned=$scanned; Skipped= @($skipped.Keys) }";

  // The script stops itself at its internal budget; the process is given headroom on top so the
  // partial result can still be serialised out instead of being killed mid-write.
  const res = await runPowerShell<Record<string, unknown>>(script, { timeoutMs: options.timeoutMs + 20_000, depth: 4 });
  if (!res.ok) {
    const message = res.error ?? "portable scan failed";
    return { programs: [], scanned: 0, skipped_paths: [], timedOut: message.includes("timed out"), error: message };
  }

  const data = (res.data ?? {}) as { Found?: unknown; Scanned?: unknown; Skipped?: unknown };
  const found = asArray<Record<string, unknown>>(data.Found);
  const timedOut = found.length === 0 && Number(data.Scanned ?? 0) === 0;

  const programs = found.map((row) => {
    const product = String(row.Product ?? "").trim();
    const version = String(row.ProductVersion ?? "").trim();
    const path = String(row.File ?? "") || null;
    return {
      source: "portable" as const,
      name: product === "" ? "unknown" : product,
      version: normVersion(version) || null,
      publisher: String(row.Company ?? "").trim() || null,
      install_source: null,
      package_id: null,
      path,
      registry_key: null,
      uninstall_string: null,
      ...(isInstallerArtifact(path) ? { installer_artifact: true } : {}),
    };
  });

  const skipped = asArray<string>(data.Skipped).map(String).filter((p) => p !== "");

  return {
    programs,
    scanned: Number(data.Scanned ?? programs.length),
    skipped_paths: skipped.slice(0, 40),
    timedOut,
  };
}

/**
 * Whether a portable `.exe` is a downloaded installer rather than an installed program.
 *
 * The live beta found Notepad++ 7.54 twice from `npp.7.5.4.Installer.exe` files sitting in document
 * folders: archive residue of a download, with no registry key and no uninstall string behind it.
 * A `*installer*.exe` / `*setup*.exe` outside Program Files is tagged `installer_artifact` and never
 * becomes a security to-do; inside Program Files an installer may legitimately be the install
 * itself, so the tag stays off there.
 */
export function isInstallerArtifact(path: string | null): boolean {
  if (path === null) return false;
  if (/program\sfiles/i.test(path)) return false;
  const file = path.split(/[\\/]/).pop() ?? "";
  return /\.(exe)$/i.test(file) && /(installer|setup)/i.test(file);
}

/**
 * Drive letters that are worth walking: fixed disks only, so network and removable drives stay out
 * by default.
 *
 * The answer is reported rather than swallowed: an empty list means the host exposed no fixed disk,
 * which is the case a probe must be able to distinguish from "walked the disks, found nothing".
 */
export async function fixedRoots(timeoutMs = 30_000): Promise<{ roots: string[]; error?: string }> {
  const script =
    "Get-CimInstance -ClassName Win32_LogicalDisk -ErrorAction SilentlyContinue | " +
    "Where-Object { $_.DriveType -eq 3 } | ForEach-Object { $_.DeviceID }";
  const res = await runPowerShell<string>(script, { timeoutMs });
  if (!res.ok) {
    return { roots: ["C:\\\\"], error: `${res.error ?? "drive query failed"} — falling back to C:\\` };
  }
  const roots = asArray<string>(res.data).map((d) => `${String(d).replace(/\\+$/, "")}\\\\`);
  return roots.length > 0
    ? { roots }
    : { roots: ["C:\\\\"], error: "Win32_LogicalDisk reported no fixed drive — falling back to C:\\" };
}
