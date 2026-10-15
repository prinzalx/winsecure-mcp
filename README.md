# winsecure-mcp

[![CI](https://github.com/prinzalx/winsecure-mcp/actions/workflows/ci.yml/badge.svg)](https://github.com/prinzalx/winsecure-mcp/actions/workflows/ci.yml)
[![Node](https://img.shields.io/badge/node-%E2%89%A5%2020-brightgreen)](https://nodejs.org)
[![License](https://img.shields.io/badge/license-MIT-blue)](LICENSE)

A Windows CVE-inventory MCP server for agents (Hermes, Claude Code, Codex, …): it reads what software
the machine has installed, matches it against the current CVE sources, and turns the findings into a
**persistent to-do list with an AI effort assessment** — the chain the lookup-only CVE servers do not
offer:

```
inventory → CVE hits → to-do list → AI assessment of the replacement effort
```

The server collects and rates, the human decides. There is **no automatic patching in v1** and no
writing intervention in the system: every write goes into the server's own JSON files, which is why
this server deliberately has no approval gate.

**Not in scope for v1:** drivers, DLLs, kernel/OS patches (Windows Update), automatic updates.

## Quick Start

You need [Node.js ≥ 20](https://nodejs.org) and npm. If you have never used Node before: install
it with the installer from nodejs.org, then open a terminal (PowerShell) in the cloned repository
and run the four commands below — they work from any folder.

```bash
git clone https://github.com/prinzalx/winsecure-mcp.git
cd winsecure-mcp
npm ci
npm run build
node dist/index.js
```

Started in a terminal, the server prints an ASCII logo and announces where it lives. Under an MCP
client such as Hermes it does not own a console: stdout carries the protocol and this goes to the
client's log instead.

```
█     █ ███ █   █ █████ █████  ████ █   █ ████  █████
█     █  █  ██  █ █     █     █     █   █ █   █ █
█  █  █  █  █ █ █  ███  ████  █     █   █ ████  ████
█ █ █ █  █  █  ██     █ █     █     █   █ █ █   █
 ██ ██  ███ █   █ █████ █████  ████  ███  █  ██ █████
  version         v0.3.0
  data directory  C:\Users\<user>\AppData\Roaming\winsecure-mcp
  store file      C:\Users\<user>\AppData\Roaming\winsecure-mcp\winsecure.json
  dashboard       http://127.0.0.1:8788
  MCP transport   stdio — this terminal stays attached to the agent
```

Open <http://127.0.0.1:8788> in a browser for the **web dashboard**: inventory and to-do statistics,
the severity breakdown, the top risks KEV-first, an activity log of every call this server session
answered, and the eight tools with their full docs. Its two buttons run `scan_inventory` and
`check_cves` through the same handlers an agent calls, so the page can never disagree with a tool
answer. `--no-web` (or `WSMD_NO_WEB=1`) keeps it stdio-only; `--port` / `WSMD_PORT` move it off 8788.

### Two ways to run it

| Mode | Command | Who connects |
|---|---|---|
| **stdio** (default) | `node dist/index.js` | a client that spawns the server as its own child process |
| **HTTP** | `node dist/index.js --http` | a client that connects by `url:` — the server is a long-lived process on the Windows host |

In HTTP mode the MCP endpoint is `POST /mcp` (Streamable HTTP with real sessions) and the server
binds `0.0.0.0` by default so a client outside the Windows network namespace — WSL — reaches it.
`--host` / `WSMD_HOST` set the bind address explicitly, `--port` / `WSMD_PORT` the port (default
**8788**, since winadmin-mcp owns 8787). The dashboard answers on the same port; `--no-web` turns
only the dashboard off, never `/mcp`.

**Why HTTP exists:** a client that spawns the server per stdio runs it in *its own* environment. On a
WSL-hosted agent that means a Linux node looks for `powershell.exe`, `winget.exe` and the drive roots
and finds none of them, so the inventory comes back `degraded` with zero programs. `scan_inventory`
reports this honestly in its `environment` block (`platform`, `node`, `powershell_found`,
`winget_found`) instead of claiming a clean "0 programs". Running the server on the Windows side and
connecting by `url:` is the intended setup on such a host.

## The Tools

| Tool | Purpose |
|---|---|
| `scan_inventory` | Refresh the inventory (sources selectable); returns per-source counters + the dedup result |
| `check_cves` | Match the inventory against the CVE sources; fill/refresh the to-do list |
| `list_todos` | Sorted KEV first, then severity/EPSS; filterable by status |
| `assess_todo` | Effort assessment for one entry (sampling client → verdict; else evidence package) |
| `save_assessment` | Write the assessment back (the non-sampling path) |
| `get_program` | Detail view of one finding (sources, paths, versions, assigned CVEs) |
| `cve_detail` | NVD lookup of a single CVE |
| `reset_todos` | Clear the whole list, or reset one entry to open (the way back to an empty list) |

Every answer is wrapped the same way: a human summary line plus `structuredContent`, with english
status words and ISO-8601 UTC timestamps throughout, so the output is **locale-independent**. An empty
result is an answer, not an error.

Beyond the tools, the store file is exposed as a read-only MCP **resource** (`winsecure://store.json`),
so an agent can inspect the inventory and to-do JSON without invoking a tool. `check_cves` reports
`cvelist.index_coverage` (local CVEs vs. the estimated full corpus), which tells "no hits found" apart
from "the local index is still thin".

## Inventory Sources

1. **Registry Uninstall keys** — HKLM + HKCU including WOW6432Node.
2. **`winget list`** — for store/winget-managed apps; the package id is carried along because it helps
   matching. Note: winget 1.29 has **no JSON output** (`--format json` errors), so the table text is
   parsed by locating the separator line and splitting columns on two-or-more spaces.
3. **Portable apps** — a bounded walk over the fixed drives for `.exe` files with FileVersionInfo.
   Excludes are mandatory and config-extensible (`C:\Windows`, `WinSxS`, `node_modules`,
   `$Recycle.Bin`, TEMP); the result is cut at `portableMaxResults` and the visited paths are reported.
   Access-denied directories are skipped, not errors.

Deduplication runs over all three sources under a normalised (product, version) key; each finding
carries the list of sources that reported it.

## CVE Data Sources

Measured live against the running APIs (Phase 0, 10/2026):

| Source | Role | Finding |
|---|---|---|
| **cvelistV5** (GitHub) | **primary** local CVE source | Full corpus is 602 MB, so the hourly **delta** (~5 MB) is downloaded and *accumulated* into a local index (`cache/cvelist-index.json`); coverage grows over days without the full download. CVE 5.0 schema (`containers.cna/adp`, `affected[].product/versions`). |
| **CISA KEV** JSON feed | actively-exploited signal | Daily-cached. An exact product-name match hits only ~0.5 % of a real inventory (display name vs CVE product name), so an alias table + `match_confidence` bridge the gap. |
| **EPSS** (FIRST) | prioritisation | Batch of ≤100 CVEs per call; fills `max_epss`. |
| **OSV.dev** batch query | not used as primary | No `Windows` ecosystem and ~0 % hit-rate on classic desktop software. |
| **NVD API 2.0** | `cve_detail` of a single CVE only | Keyless rate limit is 4 calls / 30 s; live-calls-per-program is not viable. |

Everything is cached on disk with a TTL, and **a scan run never depends on the network**. Without
network the server still returns the inventory with `cve_status: "unknown"`. Privacy: only product,
version and (when present) package id leave the machine — never paths, usernames or hostnames.

## The Assessment Mechanism (§5)

The server owns no LLM. At the handshake it checks whether the client declared the MCP `sampling`
capability:

- **Yes:** `assess_todo` asks the client directly via sampling and stores the verdict itself.
- **No (fallback, always available):** `assess_todo` returns a structured **evidence package** plus the
  fixed schema; the client assesses and writes the result back through `save_assessment`.

Both paths produce byte-for-byte the same stored shape, on exactly these axes:

| Axis | Meaning |
|---|---|
| (a) `exe_swap_only` | the fix is reached by replacing the `.exe`/file alone |
| (b) `new_setup_needed` | a new setup package from the vendor is required |
| (c) `breaking_change_expected` | a breaking change is expected |
| (d) `affected_part` | only a part program of a suite is affected → name it |

## Configuration

Defaults work out of the box; the server writes them out on first save.

| Setting | Meaning | Default |
|---|---|---|
| `dataDir` | store, caches and config | `%APPDATA%\winsecure-mcp` |
| `kevTtlHours` / `cvelistTtlHours` / `epssTtlHours` | disk-cache TTLs | 24 |
| `portableExcludes` | paths never walked | see above |
| `portableMaxResults` | cut-off for the portable walk | 40 |
| `portableTimeoutMs` | portable walk budget | 60000 |
| `httpTimeoutMs` | per outbound request | 15000 |

Environment overrides: `WSMD_CONFIG` (config file), `WSMD_DATA_DIR` (data directory),
`WSMD_OFFLINE=1` (switch the network off — the offline test), `WSMD_HTTP=1` / `WSMD_HOST` /
`WSMD_PORT` (HTTP mode, its bind address and port), `WSMD_NO_WEB` (the dashboard). CLI
`--http` / `--host` / `--config` / `--data-dir` / `--port` / `--no-web` win.

## Development

```bash
npm run typecheck   # tsc --noEmit
npm run build       # → dist/ (+ webui.html)
npm test            # build + node --test tests/*.test.mjs
node scripts/e2e.mjs --assess   # full real stdio run on this host
node scripts/sampling-test.mjs  # proves both assessment paths
node scripts/http-test.mjs      # spawns --http and drives a real session on /mcp
node scripts/banner.mjs  # regenerate the console logo
```

### End-to-end run on a Windows 11 test host (real numbers)

```
scan_inventory → 357 programs after dedup (registry 205, winget 209, portable 40 cut at max)
check_cves     → 10 CVE hits on 6 programs, 10 actively exploited; cvelist index 1991 CVEs / 1169 products
list_todos     → WhatsApp (KEV, EPSS 0.68), Microsoft Edge (×2, KEV, EPSS 0.83), 7-Zip, Git, Notepad++
assess_todo    → evidence package returned (client cannot sample); saved via save_assessment
cve_detail     → CVE-2024-21412: CVSS 8.1 — Internet Shortcut Files Security Feature Bypass
```

Offline test (`WSMD_OFFLINE=1`, cold cache): inventory 357 programs, `cve_status: "unknown"`,
`source_errors: ["offline","offline"]`, no failures.

A second probe ran the server in a Linux (WSL) sandbox where neither `powershell.exe` nor
`winget.exe` is reachable. That is what shaped the source-health rule: a scan on a host it cannot
see now reports `degraded: true`, names every source that contributed nothing (missing interpreter,
no fixed drive) and adds the `environment` block, instead of claiming a clean "0 programs".

## Matching Honesty (v0.3.0)

Two rules keep the hit list trustworthy, both of them visible in the answer rather than buried:

- **A KEV product-name match is version-checked.** The KEV feed carries no version range, so the hit
  is verified against the local CVE record: outside the affected range it is **dropped** (Chrome
  120 hit `CVE-2020-16017`, which NVD limits to Chrome *prior to 86.0.4240.198*), and when no range
  can be evaluated the hit is kept **unconfirmed** — `match_confidence: "low"`, listed in
  `unconfirmed_cves`, and it does not lift `max_severity`. `check_cves` counts them separately.
- **A KEV hit is never rendered `severity: "none"` as if that were a fact.** Whatever the local index
  does not score is completed from the disk-cached NVD helper before the to-do is built
  (`nvd_enriched` in the answer), and a hit that stays unscored carries `cvss_source:
  "nvd_unreachable"` / `"nvd_no_score"` so hit level and to-do level cannot disagree.

### Registration in Hermes

Run the server on the Windows host and connect by url, the same way winadmin-mcp is connected:

```yaml
  winsecure:
    url: http://172.28.176.1:8788/mcp
    enabled: true
```

`172.28.176.1` is the Windows side of the `vEthernet (WSL)` adapter, i.e. the address a WSL Hermes
reaches. Open the port for the WSL subnet only — not for every interface:

```powershell
netsh advfirewall firewall add rule name="winsecure-mcp" dir=in action=allow protocol=TCP localport=8788 remoteip=172.28.160.0/20
```

The old stdio entry (`command: node`, `args: [.../dist/index.js]`) is what caused the empty
inventory, because it started the server inside WSL; replace it with the `url:` form above.

Register with `manage_connections install`, then — after any server restart —
`manage_connections enable`. **Note:** Hermes is not installed on this host, so the registration and
the live sampling path could not be exercised here; the tools were all proven callable over real
stdio MCP (`scripts/e2e.mjs` lists and calls all 8) and over HTTP (`scripts/http-test.mjs`), and the
sampling path is proven with a mock-capable client (`scripts/sampling-test.mjs`). Hermes uses the
tool-name prefix `mcp__winsecure__`; match on the name behind the prefix.

## Project Structure

```
src/
  index.ts            MCP server, stdio + Streamable HTTP transports, sampling handshake, dashboard
  dashboard.ts        dashboard state + the in-memory activity ring buffer
  webui.html          the dashboard page (copied to dist/ by the build)
  config.ts           defaults + config file + CLI/env overrides
  model.ts            domain types (english, locale-independent, ISO-8601 UTC)
  store.ts            single JSON file for inventory + to-do list (atomic rename)
  utils/              result wrapper, powershell, net (TTL disk cache), matching, zip
  modules/inventory/  sources (registry/winget/portable) + dedupe
  modules/cves/       feeds (KEV/cvelistV5/EPSS/NVD) + matching engine
  modules/todos/      todo model (schema, evidence, merge) + tools
skills/windows-cve-triage/SKILL.md
```

The dashboard binds to `127.0.0.1` in stdio mode, and its run endpoint goes through the same tool
handlers, so the "only writes to its own files" rule holds on the web path too. In `--http` mode the
same port serves `/mcp` and the dashboard on the public bind address.
