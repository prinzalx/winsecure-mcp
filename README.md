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
██╗    ██╗██╗███╗   ██╗███████╗███████╗ ██████╗██╗   ██╗██████╗ ███████╗   ███╗   ███╗ ██████╗██████╗
██║    ██║██║████╗  ██║██╔════╝██╔════╝██╔════╝██║   ██║██╔══██╗██╔════╝   ████╗ ████║██╔════╝██╔══██╗
██║ █╗ ██║██║██╔██╗ ██║███████╗█████╗  ██║     ██║   ██║██████╔╝█████╗     ██╔████╔██║██║     ██████╔╝
██║███╗██║██║██║╚██╗██║╚════██║██╔══╝  ██║     ██║   ██║██╔══██╗██╔══╝     ██║╚██╔╝██║██║     ██╔═══╝
╚███╔███╔╝██║██║ ╚████║███████║███████╗╚██████╗╚██████╔╝██║  ██║███████╗   ██║ ╚═╝ ██║╚██████╗██║
 ╚══╝╚══╝ ╚═╝╚═╝  ╚═══╝╚══════╝╚══════╝ ╚═════╝ ╚═════╝ ╚═╝  ╚═╝╚══════╝   ╚═╝     ╚═╝ ╚═════╝╚═╝
  version         v0.6.5
  data directory  C:\Users\<user>\AppData\Roaming\winsecure-mcp
  store file      C:\Users\<user>\AppData\Roaming\winsecure-mcp\winsecure.json
  web interface   http://0.0.0.0:8788
  MCP transport   stdio — this terminal stays attached to the agent
```

Open <http://127.0.0.1:8788> in a browser for the **web dashboard**: inventory and to-do statistics,
the severity breakdown, the top risks confirmed-KEV-first, an activity log of every call this server session
answered, and the eight tools with their full docs. Its two buttons run `scan_inventory` and
`check_cves` through the same handlers an agent calls, so the page can never disagree with a tool
answer. A **NVD API key** section shows the current lookup mode as a badge, takes a pasted key
(validated against NVD before it is saved) and clears it again; the key itself never travels back to
the browser. `--no-web` (or `WSMD_NO_WEB=1`) keeps it stdio-only; `--port` / `WSMD_PORT` move it off 8788.

### One process, two transports (the winadmin model)

Every start of `node dist/index.js` is a long-lived process that offers **both** transports at
once, behind one listener:

| Path | Purpose |
|---|---|
| `stdio` | the default MCP transport; a client may spawn the server as its own child process |
| `POST /mcp` | MCP over Streamable HTTP with real sessions; a client connects by `url:` |
| `/`, `/api/*` | the dashboard and its JSON endpoints |

The server binds `0.0.0.0` by default so a client outside the Windows network namespace — WSL —
reaches it. `--host` / `WSMD_HOST` set the bind address explicitly, `--port` / `WSMD_PORT` the port
(default **8788**, since winadmin-mcp owns 8787). `--no-web` turns the listener off entirely, so
then only stdio remains. Everything else on the port — including a bare `curl` to `/mcp` — belongs
to the MCP transport and answers in JSON (a bare `curl` gets its `406 Not Acceptable` back, exactly
like winadmin); the dashboard HTML lives on `/`.

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
| `list_todos` | Sorted confirmed-KEV first, then confirmed findings, then severity/EPSS; filterable by status |
| `assess_todo` | Effort assessment for one entry (sampling client → verdict; else evidence package) |
| `save_assessment` | Write the assessment back (the non-sampling path) |
| `get_program` | Detail view of one finding (sources, paths, versions, assigned CVEs) |
| `cve_detail` | NVD lookup of a single CVE |
| `reset_todos` | Clear the whole list, or reset one entry to open (the way back to an empty list) |

Every answer is wrapped the same way: a human summary line plus `structuredContent`, with english
status words and ISO-8601 UTC timestamps throughout, so the output is **locale-independent**. An empty
result is an answer, not an error.

Beyond the tools, the store file is exposed as a read-only MCP **resource** (`winsecure://store.json`),
so an agent can inspect the inventory and to-do JSON without invoking a tool. Every `check_cves`
answer names its `mode` (keyed NVD or the keyless fallback) and the `product_cache` counters, which
tell "no hits found" apart from "the answer was thin"; `list_todos` repeats the mode of the run that
produced the list.

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

| Source | Role | Notes |
|---|---|---|
| **NVD API 2.0** | **primary** — one query per installed product | `keywordSearch` on the product name, paged at 2000 per request. With an API key the limit is 50 requests / 30 s, keyless 5 / 30 s; since v0.6.3 the requests are paced to the window and an HTTP 429 pauses the whole queue (see Cold Start below). Answers are cached per product with their `lastModified`, so later runs transfer only what changed. |
| **OSV.dev** batch query | keyless fallback | `POST /v1/querybatch` answers the whole inventory in one request without a key. Covers OSS-packaged software well, proprietary Windows software poorly. |
| **cvelistV5** (GitHub) | fallback index, loaded in every mode | The pre-v0.6.0 model: hourly **delta** (~5 MB) accumulated into `cache/cvelist-index.json`. Since v0.6.3 it is merged into every keyed and keyless answer (deduplicated by CVE id), so a keyed cold start never answers fewer hits than a keyless one. |
| **CISA KEV** JSON feed | actively-exploited signal | Fully local in both modes — only ~1 700 entries, so it is the cheap critical signal. An exact product-name match hits only ~0.5 % of a real inventory (display name vs CVE product name), so an alias table + `match_confidence` bridge the gap. |
| **EPSS** (FIRST) | prioritisation | Batch of ≤100 CVEs per call; fills `max_epss`. |

### How the CVE lookup works (since v0.6.0)

Earlier releases were **corpus-centric**: download the cvelistV5 deltas, accumulate them into one
local index, and grep that index for the installed products. On a fresh install that index starts
at under 1 % coverage and takes days to grow, so "no vulnerability found" and "the CVE is not in
the index yet" were indistinguishable — and the server stored a 602 MB library to answer questions
about ~350 programs.

Now the **inventory drives the lookup**. For each product name the inventory reports (deduplicated
on the normalised name, installer artifacts excluded), `check_cves`:

1. queries NVD for the CVE records that mention the product, paged, and filters them locally to the
   product names that entry is known under;
2. stores the answer in `cache/products.json` under the product's newest `lastModified`;
3. on the next run asks only for changes since that timestamp (`lastModStartDate` /
   `lastModEndDate`, inside NVD's 120-day window);
4. applies the v0.5.x version verdict against the fetched affected ranges, so
   `dropped_by_verdict` rejects a already-patched version from **complete** data on day one;
5. merges the cvelistV5 delta index in (since v0.6.3, deduplicated by CVE id), so ids the NVD
   keyword search missed still produce hits — marked with their fallback source.

Whether step 1 runs keyed or the whole thing falls back to a single OSV batch depends on the NVD
API key: **`NVD_API_KEY`** in the environment wins, otherwise the key saved in the dashboard is
used, then a single-line `nvd_api_key` file in the data directory (for hosts where the dashboard
is not reachable), otherwise the server runs keyless and says so — on the console
(`no valid NVD API key — check dashboard`) and in every answer (`mode:
"nvd-keyed" | "keyless-osv+cached"`). [`docs/nvd-key-vs-keyless.md`](docs/nvd-key-vs-keyless.md)
compares the two in one table: cost, speed, completeness, update semantics.

Everything is cached on disk with a TTL, and **a scan run never depends on the network**. Without
network the server still returns the inventory with `cve_status: "unknown"`. Privacy: only product,
version and (when present) package id leave the machine — never paths, usernames or hostnames.

### Cold Start / first run (since v0.6.3)

The **first run needs time**, especially keyed: 425 products at NVD's 50-requests-per-30-window
are minutes of work, not seconds. `check_cves` therefore does not block until the last product —
it answers after a time budget (`nvdCallBudgetMs`, default 20 s, well under a typical MCP client
transport timeout), products with a KEV hit asked first, and the rest stays in a **persistent
queue** the server works on its own: an idle-drain timer (`nvdIdleDrainMs`) keeps fetching between
calls, so progress no longer depends on how often a client happens to call.

Two rules make the queue finish instead of circling (both since v0.6.5):

- **Position is stored per product.** Every product carries its queue state (`pending`, `done`,
  `not_found`, `failed_transient`) with attempt count and time. A product that fails moves to the
  **back** of the queue, so the next call starts at the products that have never been asked — not
  again at 7-zip, git, edge, whatsapp. `product_cache.deferred` is the queue's open remainder and
  falls towards 0 across runs.
- **A 404 is a real answer when its body is an NVD envelope** ("this product matches zero CVEs"): it
closes the product for `nvdNotFoundTtlHours` (default 7 days) and counts as `not_found`, not as a
failure and never as an enrichment. A 404 with an empty or foreign body — the key-flakiness and
Cloudflare shapes — stays transient and is retried.

The answer says how far it got:

```json
"completeness": {
  "status": "incomplete",
  "warming_up": true,
  "reasons": ["425 of 425 product lookups unanswered", "212 product(s) rate limited (HTTP 429)"],
  "lookups": { "total": 425, "cached": 13, "deferred": 0, "failed_429": 212, "failed_404": 4, "failed_other": 3, "not_found": 6 },
  "hint": "Results incomplete — the NVD data was not fully reached (cold cache and/or rate limits). This is NOT \"patched\": re-run check_cves after a few minutes and compare before drawing a conclusion."
}
```

**Few hits right after installation mean the data source was not fully reached yet, not
"patched".** Check `completeness.status` (and the additive `checked_data` field, which sits next
to the untouched `cve_status`) before concluding; while `warming_up` is true the server is still
fetching on its own, so simply looking again after a few minutes is enough. Progress is visible in
`product_cache` (`products_cached` climbing, `deferred` falling towards 0) and on the dashboard's
activity log, which since v0.6.3 names the product behind every per-product HTTP 429/404 (lines
marked `(idle drain)` come from the background timer rather than a call).

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
| `nvdApiKey` | NVD key saved from the dashboard (empty = keyless) | `null` |
| `nvdProductsPerRun` | how many product answers one `check_cves` may refresh at NVD | 400 |
| `nvdMaxPages` | page cap per product query, so Chrome cannot turn into 60 requests | 5 |
| `nvdRatePerWindow` / `nvdWindowMs` | keyed NVD pacing: requests per window (NVD's documented keyed limit) | 50 / 30000 |
| `nvdConcurrency` | NVD requests in flight at the same time | 1 |
| `nvdJitterPct` | randomised extra spacing per NVD request, in percent of the window interval — keeps a queue from leaving its pause as a salvo (v0.6.5) | 20 |
| `nvdBackoffCapMs` | upper bound of the exponential 429 backoff | 60000 |
| `nvdIdleDrainMs` | period of the server-side idle drain that works the NVD queue between calls (v0.6.5) | 30000 |
| `nvdIdleDrainBatch` | open products one idle-drain tick processes at most (v0.6.5) | 5 |
| `nvdCallBudgetMs` | time budget of the per-product walk inside one `check_cves` call; the rest stays queued for the idle drain | 20000 |
| `nvdNotFoundTtlHours` | how long a zero-match (`not_found`) NVD answer is trusted | 168 |
| `portableExcludes` | paths never walked | see above |
| `portableMaxResults` | cut-off for the portable walk | 40 |
| `portableTimeoutMs` | portable walk budget | 60000 |
| `httpTimeoutMs` | per outbound request | 15000 |

Environment overrides: `WSMD_CONFIG` (config file), `WSMD_DATA_DIR` (data directory),
`WSMD_OFFLINE=1` (switch the network off — the offline test), `WSMD_HOST` / `WSMD_PORT` (the
listener's bind address and port), `WSMD_NO_WEB` (the dashboard), `NVD_API_KEY` (overrides the key
saved in the config), plus an `nvd_api_key` file in the data directory as the last fallback. CLI
`--host` / `--config` / `--data-dir` / `--port` / `--no-web` win.

## Development

```bash
npm run typecheck   # tsc --noEmit
npm run build       # → dist/ (+ webui.html)
npm test            # build + node --test tests/*.test.mjs
node scripts/e2e.mjs --assess   # full real stdio run on this host
node scripts/sampling-test.mjs  # proves both assessment paths
node scripts/http-test.mjs      # drives a real MCP session on /mcp over HTTP
node scripts/banner.mjs  # regenerate the console logo
```

### End-to-end run on a Windows 11 test host (real numbers)

```
scan_inventory → 357 programs after dedup (registry 205, winget 209, portable 40 cut at max)
check_cves     → mode nvd-keyed, product cache answers the whole inventory in one run
list_todos     → the v0.5.0 verdict rules turned this run's 6 false positives into 1 unconfirmed row
assess_todo    → evidence package returned (client cannot sample); saved via save_assessment
cve_detail     → CVE-2024-21412: CVSS 8.1 — Internet Shortcut Files Security Feature Bypass
```

The live beta (v0.4.0) produced six to-dos on this host and **all six were unconfirmed name
matches, none an actual exposure**: two Edge versions matched the same two 2016 EdgeHTML CVEs as
two separate rows, WhatsApp 2.2639 a 2019 CVE, Git 2.55 a CVE affecting Git < 2.50.1, 7-Zip 26.02 a
CVE affecting < 24.07, and Notepad++ 7.54 came from two installer `.exe` files in document folders.
After the v0.5.0 verdict rules the verification run on the same host reports `8 name match(es)
rejected by the version verdict` and **one remaining to-do**. Edge, both WhatsApp CVEs, Git and
Notepad++ are gone. The survivor is 7-Zip 26.02 vs CVE-2025-0411: the affected range (< 24.07) is
not in the thin 0.7 % index yet, and KEV membership exempts the pair from the era heuristic, so a
known-patched program stays as one low-confidence unconfirmed row rather than a claim of exposure.
That is the intended leniency for KEV entries, not a hit ranked above a confirmed one.

Offline test (`WSMD_OFFLINE=1`, cold cache): inventory 357 programs, `cve_status: "unknown"`, the
failure reason reported once per distinct message in `source_errors`, no failures. The same run
keyless (no `NVD_API_KEY`, no saved key) reports `mode: "keyless-osv+cached"` and carries the
keyless hint in `source_errors`, so a thin answer is never read as a clean machine.

A second probe ran the server in a Linux (WSL) sandbox where neither `powershell.exe` nor
`winget.exe` is reachable. That is what shaped the source-health rule: a scan on a host it cannot
see now reports `degraded: true`, names every source that contributed nothing (missing interpreter,
no fixed drive) and adds the `environment` block, instead of claiming a clean "0 programs".

## Matching Honesty (v0.3.0, verdict rules extended in v0.5.0)

Rules that keep the hit list trustworthy, all of them visible in the answer rather than buried:

- **A KEV product-name match is version-checked.** The KEV feed carries no version range, so the hit
  is verified against the local CVE record: outside the affected range it is **dropped** (Chrome
  120 hit `CVE-2020-16017`, which NVD limits to Chrome *prior to 86.0.4240.198*), and when no range
  can be evaluated the hit is kept **unconfirmed** — `match_confidence: "low"`, listed in
  `unconfirmed_cves`, and it does not lift `max_severity`. `check_cves` counts them separately.
- **A name-only match must also be plausible for its era (v0.5.0).** The delta index only ever
  accumulates recent CVEs, so an old CVE (a 2016 EdgeHTML bug, a 2019 WhatsApp bug) may never get
  local range data at all. When a KEV name match has no range that confirmed it **and** the
  installed version's era sits clearly above the CVE's publication year, the pair is impossible on
  its face and drops before it can become a to-do. Everything the verdict rejected counts up as
  `dropped_by_verdict`, so the filtering is visible instead of silent.
- **Several installed versions of one product are ONE to-do (v0.5.0).** Edge 152 and Edge 155 are
  the same finding: the to-do represents the newest version and lists the members in `versions`, so
  the list has no near-duplicate rows per version.
- **An installer archive is not installed software (v0.5.0).** A `*installer*.exe` / `*setup*.exe`
  the portable walk found outside Program Files is tagged `installer_artifact` (a downloaded setup in
  a document folder); if no other source reported the program, `check_cves` skips it
  (`installer_artifacts_skipped`).
- **A KEV hit is never rendered `severity: "none"` as if that were a fact.** Whatever the local index
  does not score is completed from the disk-cached NVD helper before the to-do is built
  (`nvd_enriched` in the answer), and **one NVD answer is applied to every hit object of that CVE
  id** (v0.5.0 — the live beta saw the same CVE scored on one to-do and null on another). A hit that
  stays unscored carries `cvss_source: "nvd_unreachable"` / `"nvd_no_score"` so hit level and to-do
  level cannot disagree.
- **Ranking never puts an unverified hit above a confirmed one (v0.5.0).** `list_todos` and the
  dashboard sort verified-KEV first, then any confirmed finding, then severity/CVSS/EPSS — an
  entry whose only KEV signal is an unconfirmed name match cannot headline the list.

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
  modules/cves/       feeds (KEV/cvelistV5/EPSS/NVD) + products.ts (per-product lookup) + matching engine
  modules/todos/      todo model (schema, evidence, merge) + tools
skills/windows-cve-triage/SKILL.md
```

One listener serves the dashboard, `/api/*` and the `/mcp` endpoint, and its run endpoint goes
through the same tool handlers, so the "only writes to its own files" rule holds on the web path
too. `--no-web` closes the listener completely; stdio keeps running either way.
