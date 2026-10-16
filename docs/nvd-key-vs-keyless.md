# NVD keyed mode vs. keyless fallback

Since v0.6.0 `check_cves` does not grep a locally accumulated CVE corpus anymore. It asks per
**installed product**: for every product name the inventory reports, the server fetches the CVE
records that mention that product, caches the answer on disk, and on later runs re-fetches only
what changed since the product's last `lastModified`. The question "is this machine affected" is
answered by ~350 product answers, not by a ~290 000-entry library.

How those product answers are obtained depends on one thing: whether an NVD API key is available.

## Where the key comes from

1. the environment variable `NVD_API_KEY` (wins when both are set),
2. otherwise the key saved in the dashboard under **NVD API key** (persisted in the config file),
3. otherwise a single-line `nvd_api_key` file in the data directory, for a host whose dashboard is
   not reachable,
4. otherwise no key, and the server runs keyless.

Without a key the console prints, at startup and on every failed key validation:

```
no valid NVD API key — check dashboard
```

A key is validated with a live NVD call before it is saved. A key that stops working (typo,
revocation) is caught by a background probe at startup, which prints the same line again rather
than querying silently into 401s.

Since v0.6.6 the probe result is a state, not a yes/no: **`valid`**, **`rejected`** or
**`unknown`** (a 429 or a network error says nothing about the key and is probed again later).
The key travels in the HTTP header `apiKey`, which is what NVD API 2.0 documents — as a query
parameter NVD rejects it with `404` and the response header `message: Invalid parameter: apiKey.`,
and an empty-body 404 with `message: Invalid apiKey.` is NVD refusing the value itself. A rejected
key is still saved and the badge turns red instead of green: the per-product requests then go out
keyless at the keyless limit, so a wrong key costs enrichment rather than all progress.

Get a key free at <https://nvd.nist.gov/developers/request-an-api-key>; NVD emails it immediately,
no approval wait in practice.

## The two modes

| | `nvd-keyed` | `keyless-osv+cached` |
|---|---|---|
| **Cost** | Free NVD API key required | Nothing, no account |
| **Requests** | One paged NVD query per product, 50 requests / 30 s | One OSV `querybatch` POST for the whole inventory, plus keyless NVD (5 requests / 30 s) used sparingly |
| **Speed** | Cold start of ~350 products takes a few minutes; later runs only touch the products a scan added (the per-run budget `nvdProductsPerRun` caps it) | Cold start is one batch call, so it is fast — but it answers only the products OSV knows |
| **Completeness** | Full NVD coverage for every installed product on day one, including vendor-only products with real CPE version ranges | OSV covers OSS-packaged software (git, 7-Zip, Python, Node, …). Proprietary Windows software (Office, Adobe, drivers) is largely absent, so the answer is thinner |
| **Update semantics** | Incremental per product via `lastModStartDate` / `lastModEndDate`: only CVEs changed since the stored `lastModified` are transferred | The OSV answer is refetched whole when its TTL expires; per-product cache entries age out the same way |
| **Version verdict** | Real affected ranges (`range_from` / `range_below`), so `dropped_by_verdict` rejects an already-patched version from complete data | OSV rarely carries a usable range, so most hits stay name matches and the verdict stays lenient |
| **Failure mode** | A product query that fails is reported in `source_errors` with a product count; the cached answer stays in place | Rate limits throttle the run; the result is explicitly labelled incomplete rather than clean |

`KEV` (CISA's actively-exploited list, ~1 700 entries) is fully local in both modes and is the
cheap, critical signal either way. `cve_detail` always uses NVD directly.

## How a run tells you which mode it was in

- Every `check_cves` result carries `mode: "nvd-keyed" | "keyless-osv+cached"`, plus
  `nvd_key` (`env` / `config` / `null`), `nvd_key_status` (`valid` / `rejected` / `unknown`, since
  v0.6.6) and the `product_cache` counters
  (`products_cached`, `refreshed`, `deferred`, `fetched_at`).
- Because a rejected key keeps the mode `nvd-keyed` while its requests actually run unauthenticated,
  the mode alone is not enough: `completeness.reasons` carries `nvd_key_rejected` and the answer sets
  `completeness.needs_attention` (v0.6.6).
- `list_todos` ends with a `lookup mode:` line, read from the store, so the list describes the run
  that produced it even long after that call.
- The dashboard shows the mode as a badge in the **NVD API key** section and as a card in the
  to-do list, plus a key-present / key-source pill.
- In keyless mode every `check_cves` answer also carries this line in `source_errors`, so a thin
  answer can never be read as "no vulnerabilities":

  ```
  running keyless, not optimal — rate limits apply, results may be less complete (no valid NVD API key — check dashboard)
  ```

## Offline

A host with neither network nor a usable key keeps answering from what the per-product cache and
the KEV file already provide. Only when both are empty does `check_cves` fall back to the legacy
cvelist delta index, which it still maintains on disk. The `cvelist` block in `structuredContent`
is marked `deprecated: true` and will be dropped after one more release; `products_cached`
replaces `index_coverage` as the coverage figure.
