import { mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { join } from "node:path";

export interface CachedFetch {
  /** Body text, or `null` when nothing could be obtained (no cache and no network). */
  body: string | null;
  /** Where the body came from, which the tools report so a stale answer is visible. */
  from: "network" | "cache" | "stale_cache" | "none";
  /** Fetch timestamp in ISO-8601 UTC, from the cache entry. */
  fetched_at: string | null;
  error?: string;
}

export interface BinaryFetch {
  /** Raw bytes, or `null` when nothing could be obtained (no cache and no network). */
  body: Buffer | null;
  from: CachedFetch["from"];
  fetched_at: string | null;
  error?: string;
}

export interface Http {
  /** The disk-cache directory, so cached POSTs land next to the cached GETs. */
  readonly cacheDir: string;
  /**
   * GET with a TTL disk cache.
   *
   * A fresh cache entry is returned without touching the network. When the network fails and an
   * expired entry exists, that stale entry is still returned, because a scan run must never depend
   * on the network. Only a cold cache plus no network yields `from: "none"`.
   */
  get(url: string, ttlMs: number): Promise<CachedFetch>;
  /**
   * Same rules as `get`, but for bytes. A ZIP read through `res.text()` loses its binary content,
   * so the cache entry of a binary url is stored base64-encoded under its own file.
   */
  getBinary(url: string, ttlMs: number): Promise<BinaryFetch>;
}

/**
 * A TTL-cached JSON POST, shaped like {@link CachedFetch}.
 *
 * `Http` grew out of feed GETs, but the OSV batch endpoint is a POST whose answer deserves the
 * same disk cache (an offline run must still answer from the last batch). The cache key is
 * `url + body`, so two different query sets never share an entry, and a caller that asks twice
 * within the TTL costs no network at all.
 */
export async function postCached(
  cacheDir: string,
  url: string,
  body: string,
  ttlMs: number,
  headers?: Record<string, string>,
  timeoutMs = 15_000,
): Promise<CachedFetch> {
  const offline = process.env.WSMD_OFFLINE === "1";
  const file = join(cacheDir, `${safeName(`${url}|${body}`)}.post.cache.json`);

  let cached: { body: string; fetched_at: string } | null = null;
  try {
    const entry = JSON.parse(readFileSync(file, "utf8")) as { body?: unknown; fetched_at?: unknown };
    cached = typeof entry?.body === "string" ? { body: entry.body, fetched_at: String(entry.fetched_at ?? "") } : null;
  } catch {
    cached = null;
  }
  if (cached) {
    const age = Date.now() - Date.parse(cached.fetched_at);
    if (Number.isFinite(age) && age >= 0 && age < ttlMs) {
      return { body: cached.body, from: "cache", fetched_at: cached.fetched_at };
    }
  }

  if (!offline) {
    try {
      const res = await fetch(url, {
        method: "POST",
        headers: { "content-type": "application/json", accept: "application/json", ...headers },
        body,
        signal: AbortSignal.timeout(timeoutMs),
      });
      const text = await res.text();
      if (res.ok) {
        const entry = { body: text, fetched_at: new Date().toISOString() };
        try {
          mkdirSync(cacheDir, { recursive: true });
          writeFileSync(file, JSON.stringify(entry), "utf8");
        } catch {
          // An unwritable cache costs one more call, nothing else.
        }
        return { body: entry.body, from: "network", fetched_at: entry.fetched_at };
      }
      const detail = `HTTP ${String(res.status)}`;
      if (cached) return { body: cached.body, from: "stale_cache", fetched_at: cached.fetched_at, error: detail };
      return { body: null, from: "none", fetched_at: null, error: detail };
    } catch (cause) {
      const message = cause instanceof Error ? cause.message : String(cause);
      if (cached) return { body: cached.body, from: "stale_cache", fetched_at: cached.fetched_at, error: message };
      return { body: null, from: "none", fetched_at: null, error: message };
    }
  }

  if (cached) return { body: cached.body, from: "stale_cache", fetched_at: cached.fetched_at, error: "offline" };
  return { body: null, from: "none", fetched_at: null, error: "offline" };
}

interface CacheFile {
  /** Keyed by url. */
  [url: string]: { body: string; fetched_at: string };
}

function safeName(url: string): string {
  let h = 2166136261;
  for (let i = 0; i < url.length; i += 1) {
    h ^= url.charCodeAt(i);
    h = Math.imul(h, 16777619);
  }
  return `${(h >>> 0).toString(16)}-${url.replace(/[^a-z0-9]+/gi, "").slice(-24)}`;
}

/**
 * A disk cache in one directory, used for every outbound answer.
 *
 * One file per url keeps a partial write from destroying the whole cache, and `WSMD_OFFLINE=1`
 * switches the network off entirely, which is how the offline behaviour is tested.
 */
export function createHttp(cacheDir: string, timeoutMs: number): Http {
  const offline = process.env.WSMD_OFFLINE === "1";

  const file = (url: string): string => join(cacheDir, `${safeName(url)}.cache.json`);
  const binFile = (url: string): string => join(cacheDir, `${safeName(url)}.bin.cache.json`);

  const readCache = (url: string): { body: string; fetched_at: string } | null => {
    try {
      const entry = JSON.parse(readFileSync(file(url), "utf8")) as CacheFile[string];
      return typeof entry?.body === "string" ? entry : null;
    } catch {
      return null;
    }
  };

  const writeCache = (url: string, body: string): { body: string; fetched_at: string } => {
    const entry = { body, fetched_at: new Date().toISOString() };
    try {
      mkdirSync(cacheDir, { recursive: true });
      writeFileSync(file(url), JSON.stringify(entry), "utf8");
    } catch {
      // A cache that cannot be written costs one more fetch, nothing else.
    }
    return entry;
  };

  return {
    cacheDir,
    async get(url, ttlMs) {
      const cached = readCache(url);
      if (cached) {
        const age = Date.now() - Date.parse(cached.fetched_at);
        if (Number.isFinite(age) && age >= 0 && age < ttlMs) {
          return { body: cached.body, from: "cache", fetched_at: cached.fetched_at };
        }
      }

      if (!offline) {
        try {
          const res = await fetch(url, {
            headers: { "user-agent": "winsecure-mcp/0.1", accept: "application/json" },
            signal: AbortSignal.timeout(timeoutMs),
          });
          if (res.ok) {
            const body = await res.text();
            const entry = writeCache(url, body);
            return { body: entry.body, from: "network", fetched_at: entry.fetched_at };
          }
          const detail = `HTTP ${String(res.status)}`;
          if (cached) return { body: cached.body, from: "stale_cache", fetched_at: cached.fetched_at, error: detail };
          return { body: null, from: "none", fetched_at: null, error: detail };
        } catch (cause) {
          const message = cause instanceof Error ? cause.message : String(cause);
          if (cached) {
            return { body: cached.body, from: "stale_cache", fetched_at: cached.fetched_at, error: message };
          }
          return { body: null, from: "none", fetched_at: null, error: message };
        }
      }

      if (cached) {
        return { body: cached.body, from: "stale_cache", fetched_at: cached.fetched_at, error: "offline" };
      }
      return { body: null, from: "none", fetched_at: null, error: "offline" };
    },

    async getBinary(url, ttlMs) {
      let entry: { b64: string; fetched_at: string } | null = null;
      try {
        const parsed = JSON.parse(readFileSync(binFile(url), "utf8")) as { b64?: unknown; fetched_at?: unknown };
        entry = typeof parsed?.b64 === "string" ? { b64: parsed.b64, fetched_at: String(parsed.fetched_at ?? "") } : null;
      } catch {
        entry = null;
      }
      if (entry) {
        const age = Date.now() - Date.parse(entry.fetched_at);
        if (Number.isFinite(age) && age >= 0 && age < ttlMs) {
          return { body: Buffer.from(entry.b64, "base64"), from: "cache", fetched_at: entry.fetched_at };
        }
      }

      if (!offline) {
        try {
          const res = await fetch(url, {
            headers: { "user-agent": "winsecure-mcp/0.1" },
            signal: AbortSignal.timeout(timeoutMs * 4),
          });
          if (res.ok) {
            const body = Buffer.from(await res.arrayBuffer());
            const at = new Date().toISOString();
            try {
              mkdirSync(cacheDir, { recursive: true });
              writeFileSync(binFile(url), JSON.stringify({ b64: body.toString("base64"), fetched_at: at }), "utf8");
            } catch {
              // Same rule as the text cache: unwritable cache, one more fetch next time.
            }
            return { body, from: "network", fetched_at: at };
          }
          const detail = `HTTP ${String(res.status)}`;
          if (entry) return { body: Buffer.from(entry.b64, "base64"), from: "stale_cache", fetched_at: entry.fetched_at, error: detail };
          return { body: null, from: "none", fetched_at: null, error: detail };
        } catch (cause) {
          const message = cause instanceof Error ? cause.message : String(cause);
          if (entry) return { body: Buffer.from(entry.b64, "base64"), from: "stale_cache", fetched_at: entry.fetched_at, error: message };
          return { body: null, from: "none", fetched_at: null, error: message };
        }
      }

      if (entry) {
        return { body: Buffer.from(entry.b64, "base64"), from: "stale_cache", fetched_at: entry.fetched_at, error: "offline" };
      }
      return { body: null, from: "none", fetched_at: null, error: "offline" };
    },
  };
}
