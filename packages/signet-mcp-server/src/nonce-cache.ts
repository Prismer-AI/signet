/**
 * In-memory nonce cache with TTL for replay protection.
 * Use with `verifyRequest()` to reject duplicate nonces.
 */
export class NonceCache {
  private seen = new Map<string, number>();
  private cleanupTimer: ReturnType<typeof setInterval> | null = null;
  private ttlMs: number;
  private maxSize: number;
  private nextExpiry = Number.POSITIVE_INFINITY;

  /**
   * @param ttlMs Time-to-live for nonce entries in milliseconds. Default: 300_000 (5 min).
   * @param maxSize Maximum number of entries before oldest are evicted. Default: 100_000.
   */
  constructor(ttlMs = 300_000, maxSize = 100_000) {
    this.ttlMs = ttlMs;
    this.maxSize = maxSize;
    this.cleanupTimer = setInterval(() => this.prune(), ttlMs);
    this.cleanupTimer.unref();
  }

  /**
   * Check and record a nonce. Returns true if the nonce is fresh (not seen before).
   * Returns false if the nonce is a duplicate (possible replay).
   */
  check(nonce: string): boolean;
  check(signerPubkey: string, nonce: string): boolean;
  check(signerOrNonce: string, nonce?: string): boolean {
    const now = Date.now();
    const key = this.makeKey(signerOrNonce, nonce);
    const existing = this.seen.get(key);
    if (existing !== undefined && existing > now) {
      return false;
    }
    const expiry = now + this.ttlMs;
    this.seen.set(key, expiry);
    if (expiry < this.nextExpiry) {
      this.nextExpiry = expiry;
    }
    // Evict oldest entries if over capacity
    if (this.seen.size > this.maxSize) {
      const toRemove = this.seen.size - this.maxSize;
      const iter = this.seen.keys();
      for (let i = 0; i < toRemove; i++) {
        const key = iter.next().value;
        if (key !== undefined) this.seen.delete(key);
      }
    }
    return true;
  }

  /** Remove expired entries. */
  prune(): void {
    const now = Date.now();
    if (this.seen.size === 0) {
      this.nextExpiry = Number.POSITIVE_INFINITY;
      return;
    }
    if (this.nextExpiry > now) {
      return;
    }

    let nextExpiry = Number.POSITIVE_INFINITY;
    for (const [nonce, expiry] of this.seen) {
      if (expiry <= now) {
        this.seen.delete(nonce);
      } else if (expiry < nextExpiry) {
        nextExpiry = expiry;
      }
    }
    this.nextExpiry = this.seen.size === 0 ? Number.POSITIVE_INFINITY : nextExpiry;
  }

  /** Stop cleanup timer. Call when shutting down. */
  destroy(): void {
    if (this.cleanupTimer) {
      clearInterval(this.cleanupTimer);
      this.cleanupTimer = null;
    }
    this.seen.clear();
    this.nextExpiry = Number.POSITIVE_INFINITY;
  }

  /** Number of active entries (for testing/monitoring). */
  get size(): number {
    return this.seen.size;
  }

  private makeKey(signerOrNonce: string, nonce?: string): string {
    if (nonce === undefined) return signerOrNonce;
    return `${signerOrNonce}\u0000${nonce}`;
  }
}
