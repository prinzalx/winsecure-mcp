import assert from "node:assert/strict";
import { test } from "node:test";

import { NvdThrottle } from "../dist/utils/throttle.js";

test("a 429 with Retry-After: 0 still pauses the queue (Cloudflare sends a useless zero)", () => {
  const t = new NvdThrottle(600, false, 0, 60_000);
  const before = Date.now();
  t.rateLimited(0);
  // The backoff decides: 2^1 * 1000 ms for the first consecutive 429, not the header's zero.
  // Allow generous slack for slow CI, but it must be far above a bare "0 s".
  assert.ok(t.pausedUntilMs() - before >= 1_500, "Retry-After: 0 must not shorten the pause to nothing");
});

test("the backoff doubles per consecutive 429 and stops at the cap", () => {
  const t = new NvdThrottle(600, false, 0, 5_000);
  t.rateLimited(0);
  const first = t.pausedUntilMs();
  t.rateLimited(0);
  const second = t.pausedUntilMs();
  assert.ok(second > first, "a second 429 must pause longer than the first");
  for (let i = 0; i < 10; i += 1) t.rateLimited(undefined);
  // Way past the cap: every further 429 may only extend to the cap from NOW, never run away.
  const lateStart = Date.now();
  t.rateLimited(undefined);
  assert.ok(t.pausedUntilMs() - lateStart <= 5_000 + 50, "the backoff respects its configured cap");
});

test("a long Retry-After wins over the exponential backoff", () => {
  const t = new NvdThrottle(600, false, 0, 60_000);
  t.rateLimited(45_000);
  assert.ok(t.pausedUntilMs() - Date.now() >= 40_000, "a 45 s Retry-After must be honored");
});

test("pauseFor holds the whole queue; resume lifts every pause (v0.6.6 breaker/key states)", () => {
  const t = new NvdThrottle(600, false, 0, 60_000);
  t.pauseFor(30_000);
  assert.ok(t.pausedUntilMs() - Date.now() >= 29_000, "pauseFor sets a long pause");
  // A shorter pause must not shorten an active one — the queue keeps waiting for the longest reason.
  t.pauseFor(1_000);
  assert.ok(t.pausedUntilMs() - Date.now() >= 28_000, "a short pauseFor does not cancel a long pause");
  t.resume();
  assert.equal(t.pausedUntilMs(), 0, "resume lifts the pause so the drain may run again");
  // An offline throttle stays immediately usable either way.
  const off = new NvdThrottle(600, true, 0, 60_000);
  off.pauseFor(30_000);
  assert.equal(off.pausedUntilMs(), 0, "offline never pauses");
});

test("an offline throttle never waits", async () => {
  const t = new NvdThrottle(600, true, 200, 60_000);
  const start = Date.now();
  await t.acquire();
  await t.acquire();
  assert.ok(Date.now() - start < 50, "offline acquire resolves immediately");
});
