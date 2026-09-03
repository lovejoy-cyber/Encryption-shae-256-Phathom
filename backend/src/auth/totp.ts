/**
 * TOTP (RFC 6238) — required MFA/fallback factor for sensitive actions,
 * per THREAT_MODEL.md §4.1. Seeds are stored only in encrypted form
 * (src/lib/secretsAtRest.ts), AAD-bound to the owning user id so a seed
 * row cannot be swapped between accounts even with database write access.
 */
import { generateSecret, generateURI, verify as otpVerify } from 'otplib';
import { eq } from 'drizzle-orm';
import { db, type Database } from '../db/client.js';
import { users } from '../db/schema.js';
import { encryptAtRest, decryptAtRest } from '../lib/secretsAtRest.js';
import { appendAuditEvent } from '../audit/auditLog.js';

const ISSUER = 'PhantomVault';

function aadFor(userId: string): Uint8Array {
  return new TextEncoder().encode(`totp-secret:${userId}`);
}

export interface TotpSetup {
  secret: string;
  otpauthUri: string;
}

/** Generates a new seed and stores it encrypted, but does NOT enable MFA yet — confirmTotp() does that after the user proves possession. */
export async function setupTotp(userId: string, email: string, database: Database = db): Promise<TotpSetup> {
  const secret = generateSecret();
  const otpauthUri = generateURI({ issuer: ISSUER, label: email, secret });
  const encrypted = await encryptAtRest(new TextEncoder().encode(secret), aadFor(userId));
  await database.update(users).set({ totpSecretEncrypted: encrypted, totpEnabled: false }).where(eq(users.id, userId));
  return { secret, otpauthUri };
}

async function loadSecret(userId: string, database: Database): Promise<string | null> {
  const [user] = await database.select().from(users).where(eq(users.id, userId));
  if (!user?.totpSecretEncrypted) return null;
  const bytes = await decryptAtRest(user.totpSecretEncrypted, aadFor(userId));
  return new TextDecoder().decode(bytes);
}

/** Confirms setup by requiring one valid code, then flips totpEnabled on. */
export async function confirmTotp(userId: string, token: string, database: Database = db): Promise<boolean> {
  const secret = await loadSecret(userId, database);
  if (!secret) return false;
  const result = await otpVerify({ secret, token });
  if (result.valid) {
    await database.update(users).set({ totpEnabled: true }).where(eq(users.id, userId));
    await appendAuditEvent({ actorUserId: userId, eventType: 'totp_enabled', eventData: {} }, database);
  }
  return result.valid;
}

export async function verifyTotp(userId: string, token: string, database: Database = db): Promise<boolean> {
  const [user] = await database.select().from(users).where(eq(users.id, userId));
  if (!user?.totpEnabled) return false;
  const secret = await loadSecret(userId, database);
  if (!secret) return false;
  const result = await otpVerify({ secret, token });
  await appendAuditEvent({
    actorUserId: userId,
    eventType: result.valid ? 'totp_verify_success' : 'totp_verify_failed',
    eventData: {},
  }, database);
  return result.valid;
}

export async function isTotpEnabled(userId: string, database: Database = db): Promise<boolean> {
  const [user] = await database.select({ totpEnabled: users.totpEnabled }).from(users).where(eq(users.id, userId));
  return user?.totpEnabled ?? false;
}
