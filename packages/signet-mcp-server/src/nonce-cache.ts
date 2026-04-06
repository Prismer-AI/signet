/**
 * In-memory nonce cache with TTL for replay protection.
 * Use with `verifyRequest()` to reject duplicate nonces.
 */
export class NonceCache {
  private seen = new Map<string, number>();
  private cleanupTimer: ReturnType<typeof setInterval> | null = null;
  private ttlMs: number;

  /** @param ttlMs Time-to-live for nonce entries in milliseconds. Default: 300_000 (5 min). */
  constructor(ttlMs = 300_000) {
    this.ttlMs = ttlMs;
    this.cleanupTimer = setInterval(() => this.prune(), ttlMs);
    this.cleanupTimer.unref();
  }

  /**
   * Check and record a nonce. Returns true if the nonce is fresh (not seen before).
   * Returns false if the nonce is a duplicate (possible replay).
   */
  check(nonce: string): boolean {
    const now = Date.now();
    const existing = this.seen.get(nonce);
    if (existing !== undefined && existing > now) {
      return false;
    }
    this.seen.set(nonce, now + this.ttlMs);
    return true;
  }

  /** Remove expired entries. */
  prune(): void {
    const now = Date.now();
    for (const [nonce, expiry] of this.seen) {
      if (expiry <= now) {
        this.seen.delete(nonce);
      }
    }
  }

  /** Stop cleanup timer. Call when shutting down. */
  destroy(): void {
    if (this.cleanupTimer) {
      clearInterval(this.cleanupTimer);
      this.cleanupTimer = null;
    }
    this.seen.clear();
  }

  /** Number of active entries (for testing/monitoring). */
  get size(): number {
    return this.seen.size;
  }
}
