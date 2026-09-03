/**
 * Session model (docs/ARCHITECTURE.md §4.2): short-lived signed access
 * tokens (JWT/ES256, stateless) + opaque, DB-backed, rotated-on-use
 * refresh tokens (the actual revocation point). Refresh token reuse — a
 * revoked/already-consumed token presented again — is treated as a theft
 * signal and revokes every session on that device, not just the one
 * token, per standard OAuth2 refresh-rotation practice.
 */
import { randomBytes, createHash } from 'node:crypto';
import { eq, and, isNull } from 'drizzle-orm';
import { SignJWT, jwtVerify, importPKCS8, importSPKI, generateKeyPair, type CryptoKey as JoseCryptoKey } from 'jose';
import { db, type Database } from '../db/client.js';
import { refreshTokens, devices } from '../db/schema.js';
import { env } from '../lib/env.js';
import { appendAuditEvent } from '../audit/auditLog.js';

const ACCESS_TOKEN_TTL_SECONDS = 10 * 60;
const REFRESH_TOKEN_TTL_SECONDS = 30 * 24 * 60 * 60;

let signingKeysPromise: Promise<{ privateKey: JoseCryptoKey; publicKey: JoseCryptoKey }> | null = null;

async function getSigningKeys() {
  if (!signingKeysPromise) {
    signingKeysPromise = (async () => {
      if (env.JWT_PRIVATE_KEY_B64 && env.JWT_PUBLIC_KEY_B64) {
        const privateKey = await importPKCS8(Buffer.from(env.JWT_PRIVATE_KEY_B64, 'base64').toString('utf8'), 'ES256');
        const publicKey = await importSPKI(Buffer.from(env.JWT_PUBLIC_KEY_B64, 'base64').toString('utf8'), 'ES256');
        return { privateKey, publicKey };
      }
      if (env.NODE_ENV === 'production') {
        throw new Error('JWT_PRIVATE_KEY_B64/JWT_PUBLIC_KEY_B64 must be set in production — refusing to sign with an ephemeral dev key.');
      }
      // Dev/test only: ephemeral key pair regenerated every process start.
      // Tokens signed with it do not survive a restart and cannot be
      // verified by a second instance — exactly why production requires fixed keys above.
      const { privateKey, publicKey } = await generateKeyPair('ES256', { extractable: true });
      return { privateKey, publicKey };
    })();
  }
  return signingKeysPromise;
}

export interface AccessTokenClaims {
  sub: string;
  orgId?: string;
  role?: string;
  deviceId: string;
}

export async function issueAccessToken(claims: AccessTokenClaims): Promise<string> {
  const { privateKey } = await getSigningKeys();
  return new SignJWT({ orgId: claims.orgId, role: claims.role, deviceId: claims.deviceId })
    .setProtectedHeader({ alg: 'ES256' })
    .setSubject(claims.sub)
    .setIssuedAt()
    .setExpirationTime(`${ACCESS_TOKEN_TTL_SECONDS}s`)
    .sign(privateKey);
}

export interface VerifiedAccessToken {
  sub: string;
  orgId?: string;
  role?: string;
  deviceId: string;
  exp: number;
  iat: number;
}

export async function verifyAccessToken(token: string): Promise<VerifiedAccessToken> {
  const { publicKey } = await getSigningKeys();
  const { payload } = await jwtVerify(token, publicKey);
  return payload as unknown as VerifiedAccessToken;
}

function hashToken(token: string): string {
  return createHash('sha256').update(token).digest('hex');
}

export async function issueRefreshToken(userId: string, deviceId: string, database: Database = db): Promise<string> {
  const raw = randomBytes(32).toString('base64url');
  await database.insert(refreshTokens).values({
    userId,
    deviceId,
    tokenHash: hashToken(raw),
    expiresAt: new Date(Date.now() + REFRESH_TOKEN_TTL_SECONDS * 1000),
  });
  return raw;
}

export type RefreshResult =
  | { ok: true; accessToken: string; refreshToken: string; userId: string; deviceId: string }
  | { ok: false; reason: 'invalid' | 'expired' | 'revoked' | 'device_revoked' };

export async function rotateRefreshToken(rawToken: string, database: Database = db): Promise<RefreshResult> {
  const tokenHash = hashToken(rawToken);

  return database.transaction(async (tx) => {
    const [row] = await tx.select().from(refreshTokens).where(eq(refreshTokens.tokenHash, tokenHash)).for('update');
    if (!row) return { ok: false, reason: 'invalid' };

    // Checked first, and reported as its own specific reason: an intentional
    // device revocation should never be reported as generic token reuse, even
    // though revokeDevice() also marks this row's tokens revoked (defense in
    // depth for session-count/audit purposes) — that would otherwise trip the
    // reuse-detection branch below and mask *why* access was denied.
    const [device] = await tx.select().from(devices).where(eq(devices.id, row.deviceId));
    if (!device || device.revokedAt) return { ok: false, reason: 'device_revoked' };

    if (row.revokedAt) {
      await tx.update(refreshTokens)
        .set({ revokedAt: new Date() })
        .where(and(eq(refreshTokens.deviceId, row.deviceId), isNull(refreshTokens.revokedAt)));
      await appendAuditEvent({
        actorUserId: row.userId,
        eventType: 'refresh_token_reuse_detected',
        eventData: { deviceId: row.deviceId },
      }, tx as unknown as Database);
      return { ok: false, reason: 'revoked' };
    }

    if (row.expiresAt.getTime() < Date.now()) return { ok: false, reason: 'expired' };

    const newRaw = randomBytes(32).toString('base64url');
    const [newRow] = await tx.insert(refreshTokens).values({
      userId: row.userId,
      deviceId: row.deviceId,
      tokenHash: hashToken(newRaw),
      expiresAt: new Date(Date.now() + REFRESH_TOKEN_TTL_SECONDS * 1000),
    }).returning();

    await tx.update(refreshTokens).set({ revokedAt: new Date(), replacedBy: newRow.id }).where(eq(refreshTokens.id, row.id));
    await tx.update(devices).set({ lastSeen: new Date() }).where(eq(devices.id, row.deviceId));

    const accessToken = await issueAccessToken({ sub: row.userId, deviceId: row.deviceId });
    return { ok: true, accessToken, refreshToken: newRaw, userId: row.userId, deviceId: row.deviceId };
  });
}

export async function registerDevice(userId: string, name: string, userAgent: string | undefined, database: Database = db): Promise<string> {
  const [device] = await database.insert(devices).values({ userId, name, userAgent }).returning();
  await appendAuditEvent({ actorUserId: userId, eventType: 'device_registered', eventData: { deviceId: device.id, name } }, database);
  return device.id;
}

export async function revokeDevice(deviceId: string, actorUserId: string, database: Database = db): Promise<void> {
  await database.transaction(async (tx) => {
    await tx.update(devices).set({ revokedAt: new Date() }).where(eq(devices.id, deviceId));
    await tx.update(refreshTokens)
      .set({ revokedAt: new Date() })
      .where(and(eq(refreshTokens.deviceId, deviceId), isNull(refreshTokens.revokedAt)));
    await appendAuditEvent({ actorUserId, eventType: 'device_revoked', eventData: { deviceId } }, tx as unknown as Database);
  });
}
