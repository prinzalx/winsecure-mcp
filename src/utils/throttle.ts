/**
 * NVD request pacing for one server process (task 1, v0.6.3).
 *
 * The live beta showed why a plain sleep between requests is not enough: when the requests go out
 * in a salvo, NVD answers HTTP 429 on nearly every product, and retrying the single request does
 * not help because every other queued request would hit the same wall. So a 429 pauses the whole
 * queue through this object: later requests do not wait pointlessly at issue time but wait for
 * whatever of the pause is left when they get their turn.
 *
 * The spacing implements NVD's documented window (50 requests per 30 s with a key, 5 per 30 s
 * without): requests may start every `window_ms / rate` apart and the window count runs from the
 * first request, which a slot-based bucket models exactly. Both numbers are configurable because
 * the field evidence said the effective limit could be lower; a wrong setting is then a config
 * change, not a release.
 */
export class NvdThrottle {
  /** Epoch ms at which the next request may start (the bucket's refill line). */
  private nextSlotAt = 0;
  /** Epoch ms until which the whole queue is paused after a 429. */
  private pausedUntil = 0;
  /** Consecutive 429 answers; drives the exponential backoff. */
  private streak = 0;

  constructor(
    private readonly intervalMs: number,
    private readonly offline = false,
  ) {}

  /** Wait until the next request may go out, then take its slot. */
  async acquire(): Promise<void> {
    if (this.offline) return;
    const now = Date.now();
    const start = Math.max(now, this.nextSlotAt, this.pausedUntil);
    if (start > now) await sleep(start - now);
    this.nextSlotAt = Math.max(this.nextSlotAt, start) + this.intervalMs;
  }

  /**
   * Record an HTTP 429: `Retry-After` wins, otherwise the wait doubles per consecutive 429 (capped
   * at a minute), and the pause applies to every queued request, not just the failing one.
   */
  rateLimited(retryAfterMs: number | undefined): void {
    if (this.offline) return;
    this.streak += 1;
    const backoffMs = Math.min(2 ** Math.min(this.streak, 6) * 1_000, 60_000);
    const waitMs = Math.max(retryAfterMs ?? 0, backoffMs);
    const until = Date.now() + waitMs;
    if (until > this.pausedUntil) this.pausedUntil = until;
    if (this.pausedUntil > this.nextSlotAt) this.nextSlotAt = this.pausedUntil;
  }

  /** A answered request breaks the 429 streak, so the backoff shrinks again. */
  succeeded(): void {
    this.streak = 0;
  }
}

function sleep(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms));
}
