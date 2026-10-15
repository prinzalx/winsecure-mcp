# winsecure-mcp

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

```bash
npm ci
npm run build
node dist/index.js
```

```
  version         v0.1.0
  data directory  C:\Users\<user>\AppData\Roaming\winsecure-mcp
  store file      C:\Users\<user>\AppData\Roaming\winsecure-mcp\winsecure.json
  MCP transport   stdio — this terminal stays attached to the agent
```

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

Every answer is wrapped the same way: a human summary line plus `structuredContent`, with english
status words and ISO-8601 UTC timestamps throughout, so the output is **locale-independent**. An empty
result is an answer, not an error.

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
`WSMD_OFFLINE=1` (switch the network off — the offline test). CLI `--config` / `--data-dir` win.

## Development

```bash
npm run typecheck   # tsc --noEmit
npm run build       # → dist/
npm test            # build + node --test tests/*.test.mjs
node scripts/e2e.mjs --assess   # full real stdio run on this host
node scripts/sampling-test.mjs  # proves both assessment paths
```

### End-to-end run on DESKTOP-F74SJA6 (real numbers)

```
scan_inventory → 357 programs after dedup (registry 205, winget 209, portable 40 cut at max)
check_cves     → 10 CVE hits on 6 programs, 10 actively exploited; cvelist index 1991 CVEs / 1169 products
list_todos     → WhatsApp (KEV, EPSS 0.68), Microsoft Edge (×2, KEV, EPSS 0.83), 7-Zip, Git, Notepad++
assess_todo    → evidence package returned (client cannot sample); saved via save_assessment
cve_detail     → CVE-2024-21412: CVSS 8.1 — Internet Shortcut Files Security Feature Bypass
```

Offline test (`WSMD_OFFLINE=1`, cold cache): inventory 357 programs, `cve_status: "unknown"`,
`source_errors: ["offline","offline"]`, no failures.

### Registration in Hermes

Register with `manage_connections install`, then — after any server restart —
`manage_connections enable`. **Note:** Hermes is not installed on this host, so the registration and
the live sampling path could not be exercised here; the tools were all proven callable over real stdio
MCP (`scripts/e2e.mjs` lists and calls all 7), and the sampling path is proven with a mock-capable
client (`scripts/sampling-test.mjs`). Hermes uses the tool-name prefix `mcp__winsecure__`; match on the
name behind the prefix.

## Project Structure

```
src/
  index.ts            MCP server, stdio transport, sampling handshake
  config.ts           defaults + config file + CLI/env overrides
  model.ts            domain types (english, locale-independent, ISO-8601 UTC)
  store.ts            single JSON file for inventory + to-do list (atomic rename)
  utils/              result wrapper, powershell, net (TTL disk cache), matching, zip
  modules/inventory/  sources (registry/winget/portable) + dedupe
  modules/cves/       feeds (KEV/cvelistV5/EPSS/NVD) + matching engine
  modules/todos/      todo model (schema, evidence, merge) + tools
skills/windows-cve-triage/SKILL.md
```
