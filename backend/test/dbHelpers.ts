import { sql } from '../src/db/client.js';
import { redis } from '../src/lib/rateLimiter.js';

/** Wipes all application tables between test files so integration tests don't leak state into each other. */
export async function resetDatabase(): Promise<void> {
  await sql`TRUNCATE TABLE
    audit_log, security_events, capabilities, refresh_tokens, devices,
    webauthn_challenges, webauthn_credentials, org_members, organizations, users
    RESTART IDENTITY CASCADE`;
}

export async function resetRedis(): Promise<void> {
  await redis.flushdb();
}
