/**
 * Redis-backed abuse prevention: a fixed-window counter for general rate
 * limiting, plus an escalating-lockout helper specifically for
 * authentication endpoints (THREAT_MODEL.md §3 A6 — credential stuffing).
 */
import { Redis } from 'ioredis';
import { env } from './env.js';

export const redis = new Redis(env.REDIS_URL);

export interface RateLimitResult {
  allowed: boolean;
  remaining: number;
  resetAt: number;
}

export async function checkRateLimit(key: string, limit: number, windowSeconds: number): Promise<RateLimitResult> {
  const redisKey = `ratelimit:${key}`;
  const pipeline = redis.pipeline();
  pipeline.incr(redisKey);
  pipeline.ttl(redisKey);
  const results = await pipeline.exec();
  const count = results?.[0]?.[1] as number;
  let ttl = results?.[1]?.[1] as number;

  if (ttl === -1) {
    await redis.expire(redisKey, windowSeconds);
    ttl = windowSeconds;
  }

  return {
    allowed: count <= limit,
    remaining: Math.max(0, limit - count),
    resetAt: Date.now() + Math.max(ttl, 0) * 1000,
  };
}

const LOCKOUT_BASE_SECONDS = 5;
const LOCKOUT_MAX_SECONDS = 15 * 60;
const LOCKOUT_THRESHOLD = 5; // failures before any lockout kicks in

/** Call on every failed auth attempt. Returns the lockout window now in effect (0 = not locked). */
export async function recordFailedAuthAttempt(identifier: string): Promise<{ lockedForSeconds: number; failureCount: number }> {
  const key = `authfail:${identifier}`;
  const failureCount = await redis.incr(key);
  await redis.expire(key, LOCKOUT_MAX_SECONDS);

  if (failureCount < LOCKOUT_THRESHOLD) return { lockedForSeconds: 0, failureCount };

  const excess = failureCount - LOCKOUT_THRESHOLD;
  const lockedForSeconds = Math.min(LOCKOUT_BASE_SECONDS * 2 ** excess, LOCKOUT_MAX_SECONDS);
  await redis.set(`authlock:${identifier}`, '1', 'EX', lockedForSeconds);
  return { lockedForSeconds, failureCount };
}

export async function clearFailedAuthAttempts(identifier: string): Promise<void> {
  await redis.del(`authfail:${identifier}`, `authlock:${identifier}`);
}

export async function isAuthLocked(identifier: string): Promise<boolean> {
  return (await redis.exists(`authlock:${identifier}`)) === 1;
}
