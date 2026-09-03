import { describe, it, expect, beforeEach, afterAll } from 'vitest';
import { checkRateLimit, recordFailedAuthAttempt, clearFailedAuthAttempts, isAuthLocked, redis } from '../src/lib/rateLimiter.js';
import { resetRedis } from './dbHelpers.js';

beforeEach(resetRedis);
afterAll(async () => redis.quit());

describe('fixed-window rate limiting', () => {
  it('allows requests under the limit and blocks over it', async () => {
    const key = 'test-key-1';
    for (let i = 0; i < 5; i++) {
      const r = await checkRateLimit(key, 5, 60);
      expect(r.allowed).toBe(true);
    }
    const over = await checkRateLimit(key, 5, 60);
    expect(over.allowed).toBe(false);
  });

  it('different keys have independent counters', async () => {
    await checkRateLimit('key-a', 1, 60);
    const a = await checkRateLimit('key-a', 1, 60);
    const b = await checkRateLimit('key-b', 1, 60);
    expect(a.allowed).toBe(false);
    expect(b.allowed).toBe(true);
  });
});

describe('SECURITY REGRESSION: escalating auth lockout (credential stuffing defense)', () => {
  it('does not lock out before the failure threshold', async () => {
    for (let i = 0; i < 4; i++) await recordFailedAuthAttempt('victim@example.com');
    expect(await isAuthLocked('victim@example.com')).toBe(false);
  });

  it('locks out after the threshold is crossed', async () => {
    for (let i = 0; i < 5; i++) await recordFailedAuthAttempt('victim2@example.com');
    expect(await isAuthLocked('victim2@example.com')).toBe(true);
  });

  it('lockout duration escalates with repeated failures', async () => {
    let lastDuration = 0;
    for (let i = 0; i < 5; i++) await recordFailedAuthAttempt('escalate@example.com');
    const r1 = await recordFailedAuthAttempt('escalate@example.com');
    lastDuration = r1.lockedForSeconds;
    const r2 = await recordFailedAuthAttempt('escalate@example.com');
    expect(r2.lockedForSeconds).toBeGreaterThan(lastDuration);
  });

  it('a successful login clears the failure counter and any active lock', async () => {
    for (let i = 0; i < 5; i++) await recordFailedAuthAttempt('recovers@example.com');
    expect(await isAuthLocked('recovers@example.com')).toBe(true);
    await clearFailedAuthAttempts('recovers@example.com');
    expect(await isAuthLocked('recovers@example.com')).toBe(false);
  });

  it('lockouts for different identifiers are independent', async () => {
    for (let i = 0; i < 5; i++) await recordFailedAuthAttempt('a@example.com');
    expect(await isAuthLocked('a@example.com')).toBe(true);
    expect(await isAuthLocked('b@example.com')).toBe(false);
  });
});
