/**
 * NVD request pacing for one server process (task 1, v0.6.3; reworked for bursts in v0.6.5).
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
 *
 * A probe from WSL against the live endpoint (v0.6.5) showed the wall is actually Cloudflare in
 * front of NVD: a short burst answered `HTTP 429` with the body `error code: 1015` and a
 * `Retry-After: 0`, and the very same request succeeded 20 s later in 0,5 s. Two consequences,
 * both implemented here:
 *
 * - `Retry-After: 0` carries no information, so the exponential backoff decides the pause and the
 *   header can never shorten it to zero. The cap is configurable for the same reason the window
 *   is: an operator who sees longer bans raises it without a release.
 * - The slot line alone lets the whole interval be spent in one go after a pause. A small jitter
 *   on top of every wait keeps the requests from re-grouping into a salvo at the end of a pause.
 */
export class NvdThrottle {
  /** Epoch ms at which the next request may start (the bucket's refill line). */
  private nextSlotAt = 0;
  /** Epoch ms until which the whole queue is paused after a 429. */
  private pausedUntil = 0;
  /** Consecutive 429 answers; drives the exponential backoff. */
  private streak = 0;

  constructor(
    private intervalMs: number,
    private readonly offline = false,
    /** Extra randomised spacing per request, so a drained queue does not leave its pause as a salvo. */
    private readonly jitterMs = 0,
    /** Upper bound of the exponential backoff; a wrong guess is a config change, not a release. */
    private readonly backoffCapMs = 60_000,
  ) {}

  /**
   * Move the spacing to a new interval without losing the pause (v0.6.6).
   *
   * A rejected key paces the same queue at the keyless window; rebuilding the throttle would drop
   * the long pause the rejection just set, which is the one thing the retry storm needs.
   */
  setIntervalMs(ms: number): void {
    this.intervalMs = ms;
  }

  /** Wait until the next request may go out, then take its slot. */
  async acquire(): Promise<void> {
    if (this.offline) return;
    const now = Date.now();
    const jitter = this.jitterMs > 0 ? Math.floor(Math.random() * this.jitterMs) : 0;
    const start = Math.max(now, this.nextSlotAt + jitter, this.pausedUntil);
    if (start > now) await sleep(start - now);
    this.nextSlotAt = Math.max(this.nextSlotAt, start) + this.intervalMs;
  }

  /**
   * Record an HTTP 429: `Retry-After` wins when it actually says something (Cloudflare sends `0`),
   * otherwise the wait doubles per consecutive 429 up to the cap, and the pause applies to every
   * queued request, not just the failing one.
   */
  rateLimited(retryAfterMs: number | undefined): void {
    if (this.offline) return;
    this.streak += 1;
    const backoffMs = Math.min(2 ** Math.min(this.streak, 6) * 1_000, Math.max(1_000, this.backoffCapMs));
    const waitMs = Math.max(retryAfterMs ?? 0, backoffMs);
    const until = Date.now() + waitMs;
    if (until > this.pausedUntil) this.pausedUntil = until;
    if (this.pausedUntil > this.nextSlotAt) this.nextSlotAt = this.pausedUntil;
  }

  /** A answered request breaks the 429 streak, so the backoff shrinks again. */
  succeeded(): void {
    this.streak = 0;
  }

  /**
   * Pause the whole queue for a fixed stretch, independent of the 429 backoff (v0.6.6).
   *
   * The circuit breaker and a rejected key use this: the point is that nothing goes out at all for
   * a while, so a request shape NVD never accepts stops burning the window on retries.
   */
  pauseFor(ms: number): void {
    if (this.offline) return;
    const until = Date.now() + Math.max(0, ms);
    if (until > this.pausedUntil) this.pausedUntil = until;
    if (this.pausedUntil > this.nextSlotAt) this.nextSlotAt = this.pausedUntil;
  }

  /** Lift every pause (a probe proved the key good again): the queue may run at slot spacing. */
  resume(): void {
    this.pausedUntil = 0;
    if (this.nextSlotAt < Date.now()) this.nextSlotAt = 0;
    this.streak = 0;
  }

  /** Epoch ms until which the whole queue is paused; exposed for tests and the dashboard. */
  pausedUntilMs(): number {
    return this.pausedUntil;
  }
}

function sleep(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms));
}
