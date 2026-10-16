# Changelog

All notable changes to winsecure-mcp are documented here.

## 0.6.3 — 2026-10-16

Fixes the keyed NVD cold start reported by the live beta: a parallel salvo ate HTTP 429 on
~383 of 425 products, failed lookups counted as done, the keyed mode skipped the cvelist
fallback, and `cve_status: "checked"` let a one-hit cold start read as "almost patched".

### Throttled keyed lookups (task 1)

- All NVD product requests now pass a shared `NvdThrottle` (token-bucket pacing) instead of a
  fixed sleep. Defaults implement NVD's documented keyed window, **50 requests / 30 s**
  (`nvdRatePerWindow` / `nvdWindowMs`); an HTTP 429 honors `Retry-After`, backs off
  exponentially, and pauses the **whole queue**, not just the failing request. The live beta
  observed an effective limit nearer 5/30 under parallel load — the settings make the real
  limit a config change. NVD has no per-product bulk endpoint (`keywordSearch` is one query
  per product; the OSV `querybatch` is the keyless path), so the paced queue stays the fix.
- `check_cves` no longer blocks until the last product: the per-product walk stops at a
  per-call time budget (`nvdCallBudgetMs`, default 20 s — well under a typical MCP client
  transport timeout) and the rest of the queue drains in the **background** (or on the next
  call). Products with a KEV hit are queried first.
- `nvdConcurrency` (default 1) controls how many NVD requests run in flight.

### Failed lookups are not done (task 2)

- Transient failures (429, 404 with a key, 5xx, timeout, network) leave **no cache entry**:
  the product stays pending/deferred and is retried on a later run. Only a full answer with
  zero results caches a negative `not_found` marker with the short `nvdNotFoundTtlHours` TTL
  (default 6 h), clearly distinguishable from a successful enrichment.
- A keyless OSV cache entry no longer counts fresh in keyed mode (freshness requires
  `source: "nvd"`): it lacks CVSS and version ranges, so keyed mode re-asks NVD to enrich it.
  This was the cause of `refreshed: 0 / nvd_enriched: 0` after a key was added.
- The jumping 404 totals (17→12→3→35) are explained: with a key set, NVD answers HTTP 404
  flakily (observed live: empty body, `Invalid parameter: apiKey.`). A 404 is classified as
  transient and never cached as "no such product", so it can no longer inflate a false
  negative.

### cvelist fallback in every mode (task 3)

- The cvelistV5 delta index is loaded in **keyed mode too** (it was only consulted when the
  product cache and KEV were both empty) and merged into the per-product answers, deduplicated
  by CVE id; the per-product NVD records win on collision, the index contributes the ids the
  NVD keyword search missed. A keyed cold start now reaches at least the keyless hit baseline
  plus NVD enrichment once the queue drains. The source remains the (deprecated-marked) cvelist
  delta — a full current-corpus switch is not needed while the merge covers keyword misses.

### Result communication (task 4)

- `check_cves` answers carry a top-level **`completeness`** object:
  `{ status: "complete"|"incomplete", warming_up, reasons[], lookups: { total, cached, deferred,
  failed_429, failed_404, failed_other, not_found }, hint }`.
- Additive next to the untouched values of `cve_status`: the new `checked_data` field reports
  `"complete" | "incomplete" | "unknown"`. No existing value was re-interpreted.

### Small things (task 5)

- Per-product HTTP 429/404 failures are logged into the activity log with the product name,
  status code and timestamp, not only as an aggregate count.
- The `windows-cve-triage` skill declares `platforms: [windows, linux]` so WSL-hosted agents
  stop blocking it ("not supported on this platform").

## 0.6.2 — 2026-10-16

- Fixed the dashboard script (blank page after findings existed) and added the `nvd_api_key`
  file fallback for hosts whose dashboard is unreachable.

## 0.6.1 — 2026-10-16

- Accept UUID-format NVD API keys; fix the key-save feedback in the dashboard.

## 0.6.0 — 2026-10-16

- Inventory-driven per-product NVD lookup with a product cache (`cache/products.json`),
  keyed/keyless modes (`nvd-keyed` / `keyless-osv+cached`), version verdict, KEV-first to-do
  ordering.
