import type { FastifyInstance } from 'fastify';
import { z } from 'zod';
import { eq } from 'drizzle-orm';
import { SignJWT, jwtVerify } from 'jose';
import { db } from '../db/client.js';
import { users, devices } from '../db/schema.js';
import * as webauthn from '../auth/webauthn.js';
import * as totp from '../auth/totp.js';
import { issueAccessToken, issueRefreshToken, rotateRefreshToken, registerDevice, revokeDevice } from '../auth/sessions.js';
import { requireAuth } from '../auth/authPlugin.js';
import { recordFailedAuthAttempt, clearFailedAuthAttempts, isAuthLocked } from '../lib/rateLimiter.js';
import { appendAuditEvent } from '../audit/auditLog.js';
import { emitSecurityEvent } from '../security-events/emit.js';
import { getPendingSigningKey } from '../auth/pendingKey.js';

const rp: webauthn.RpConfig = {
  rpName: 'PhantomVault',
  rpID: process.env.RP_ID ?? 'localhost',
  origin: process.env.RP_ORIGIN ?? 'http://localhost:5173',
};

// Ephemeral signing reuses the module-local key indirectly via issueAccessToken's
// signer would leak claims we don't want on a full access token, so pending-TOTP
// tokens are minted directly here with a narrow, single-purpose payload.
async function signPendingTotpToken(userId: string, deviceId: string): Promise<string> {
  const key = await getPendingSigningKey();
  return new SignJWT({ purpose: 'totp_pending', deviceId })
    .setProtectedHeader({ alg: 'HS256' })
    .setSubject(userId)
    .setIssuedAt()
    .setExpirationTime('5m')
    .sign(key);
}

async function verifyPendingTotpToken(token: string): Promise<{ userId: string; deviceId: string }> {
  const key = await getPendingSigningKey();
  const { payload } = await jwtVerify(token, key);
  if (payload.purpose !== 'totp_pending') throw new Error('wrong token purpose');
  return { userId: payload.sub as string, deviceId: payload.deviceId as string };
}

export async function authRoutes(app: FastifyInstance) {
  app.post('/auth/register/start', async (req, reply) => {
    const body = z.object({ email: z.string().email() }).parse(req.body);
    let [user] = await db.select().from(users).where(eq(users.email, body.email));
    if (!user) {
      [user] = await db.insert(users).values({ email: body.email }).returning();
      await appendAuditEvent({ actorUserId: user.id, eventType: 'user_created', eventData: { email: body.email } });
    }
    const options = await webauthn.startRegistration(user.id, body.email, rp);
    return reply.send(options);
  });

  app.post('/auth/register/finish', async (req, reply) => {
    const body = z.object({ email: z.string().email(), response: z.any(), deviceName: z.string().default('Unnamed device') }).parse(req.body);
    const [user] = await db.select().from(users).where(eq(users.email, body.email));
    if (!user) return reply.code(404).send({ error: 'user_not_found' });

    const verification = await webauthn.finishRegistration(user.id, body.response, rp);
    if (!verification.verified) return reply.code(400).send({ error: 'verification_failed' });

    const deviceId = await registerDevice(user.id, body.deviceName, req.headers['user-agent']);
    const accessToken = await issueAccessToken({ sub: user.id, deviceId });
    const refreshToken = await issueRefreshToken(user.id, deviceId);
    await emitSecurityEvent({ userId: user.id, eventType: 'register', success: true, deviceFingerprint: deviceId });

    return reply.send({ accessToken, refreshToken, deviceId });
  });

  app.post('/auth/login/start', async (req, reply) => {
    const body = z.object({ email: z.string().email().optional() }).parse(req.body ?? {});
    const options = await webauthn.startAuthentication(body.email ?? null, rp);
    return reply.send(options);
  });

  app.post('/auth/login/finish', async (req, reply) => {
    const body = z.object({ response: z.any(), deviceName: z.string().default('Unnamed device') }).parse(req.body);
    const credentialId = body.response?.id ?? 'unknown';

    if (await isAuthLocked(credentialId)) {
      return reply.code(429).send({ error: 'account_temporarily_locked' });
    }

    const result = await webauthn.finishAuthentication(body.response, rp);
    if (!result.verified || !result.userId) {
      const { lockedForSeconds } = await recordFailedAuthAttempt(credentialId);
      await emitSecurityEvent({ eventType: 'login', success: false, deviceFingerprint: credentialId });
      return reply.code(401).send({ error: 'verification_failed', lockedForSeconds });
    }
    await clearFailedAuthAttempts(credentialId);

    const totpEnabled = await totp.isTotpEnabled(result.userId);
    const deviceId = await registerDevice(result.userId, body.deviceName, req.headers['user-agent']);

    if (totpEnabled) {
      const pendingToken = await signPendingTotpToken(result.userId, deviceId);
      return reply.send({ totpRequired: true, pendingToken });
    }

    const accessToken = await issueAccessToken({ sub: result.userId, deviceId });
    const refreshToken = await issueRefreshToken(result.userId, deviceId);
    await emitSecurityEvent({ userId: result.userId, eventType: 'login', success: true, deviceFingerprint: deviceId });
    return reply.send({ accessToken, refreshToken, deviceId });
  });

  app.post('/auth/login/totp', async (req, reply) => {
    const body = z.object({ pendingToken: z.string(), code: z.string().length(6) }).parse(req.body);
    let claims: { userId: string; deviceId: string };
    try {
      claims = await verifyPendingTotpToken(body.pendingToken);
    } catch {
      return reply.code(401).send({ error: 'invalid_pending_token' });
    }

    if (await isAuthLocked(`totp:${claims.userId}`)) {
      return reply.code(429).send({ error: 'account_temporarily_locked' });
    }

    const valid = await totp.verifyTotp(claims.userId, body.code);
    if (!valid) {
      const { lockedForSeconds } = await recordFailedAuthAttempt(`totp:${claims.userId}`);
      return reply.code(401).send({ error: 'invalid_totp_code', lockedForSeconds });
    }
    await clearFailedAuthAttempts(`totp:${claims.userId}`);

    const accessToken = await issueAccessToken({ sub: claims.userId, deviceId: claims.deviceId });
    const refreshToken = await issueRefreshToken(claims.userId, claims.deviceId);
    await emitSecurityEvent({ userId: claims.userId, eventType: 'login_totp', success: true, deviceFingerprint: claims.deviceId });
    return reply.send({ accessToken, refreshToken, deviceId: claims.deviceId });
  });

  app.post('/auth/refresh', async (req, reply) => {
    const body = z.object({ refreshToken: z.string() }).parse(req.body);
    const result = await rotateRefreshToken(body.refreshToken);
    if (!result.ok) return reply.code(401).send({ error: result.reason });
    return reply.send({ accessToken: result.accessToken, refreshToken: result.refreshToken });
  });

  app.post('/auth/totp/setup', { preHandler: requireAuth }, async (req, reply) => {
    const [user] = await db.select().from(users).where(eq(users.id, req.user!.userId));
    const setup = await totp.setupTotp(req.user!.userId, user.email);
    return reply.send(setup);
  });

  app.post('/auth/totp/confirm', { preHandler: requireAuth }, async (req, reply) => {
    const body = z.object({ code: z.string().length(6) }).parse(req.body);
    const ok = await totp.confirmTotp(req.user!.userId, body.code);
    if (!ok) return reply.code(400).send({ error: 'invalid_code' });
    return reply.send({ enabled: true });
  });

  app.get('/auth/devices', { preHandler: requireAuth }, async (req, reply) => {
    const rows = await db.select().from(devices).where(eq(devices.userId, req.user!.userId));
    return reply.send(rows);
  });

  app.post('/auth/devices/:deviceId/revoke', { preHandler: requireAuth }, async (req, reply) => {
    const params = z.object({ deviceId: z.string().uuid() }).parse(req.params);
    const [device] = await db.select().from(devices).where(eq(devices.id, params.deviceId));
    if (!device || device.userId !== req.user!.userId) return reply.code(404).send({ error: 'device_not_found' });
    await revokeDevice(params.deviceId, req.user!.userId);
    return reply.send({ revoked: true });
  });
}
