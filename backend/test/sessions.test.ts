import { describe, it, expect, beforeEach, afterAll } from 'vitest';
import { sql, db } from '../src/db/client.js';
import { users } from '../src/db/schema.js';
import {
  issueAccessToken, verifyAccessToken, issueRefreshToken, rotateRefreshToken,
  registerDevice, revokeDevice,
} from '../src/auth/sessions.js';
import { resetDatabase } from './dbHelpers.js';

let userId: string;
let deviceId: string;

beforeEach(async () => {
  await resetDatabase();
  const [user] = await db.insert(users).values({ email: 'user@example.com' }).returning();
  userId = user.id;
  deviceId = await registerDevice(userId, 'Test Device', 'vitest');
});
afterAll(async () => sql.end());

describe('access tokens', () => {
  it('issues a token that verifies back to the same claims', async () => {
    const token = await issueAccessToken({ sub: userId, deviceId });
    const claims = await verifyAccessToken(token);
    expect(claims.sub).toBe(userId);
    expect(claims.deviceId).toBe(deviceId);
  });

  it('rejects a tampered token', async () => {
    const token = await issueAccessToken({ sub: userId, deviceId });
    const tampered = token.slice(0, -4) + 'XXXX';
    await expect(verifyAccessToken(tampered)).rejects.toThrow();
  });
});

describe('refresh token rotation & revocation', () => {
  it('rotates: the old token cannot be used again after rotation', async () => {
    const raw = await issueRefreshToken(userId, deviceId);
    const first = await rotateRefreshToken(raw);
    expect(first.ok).toBe(true);

    const second = await rotateRefreshToken(raw);
    expect(second.ok).toBe(false);
    if (!second.ok) expect(second.reason).toBe('revoked');
  });

  it('SECURITY REGRESSION: reusing an already-rotated token revokes the ENTIRE device session, not just that token', async () => {
    const raw = await issueRefreshToken(userId, deviceId);
    const first = await rotateRefreshToken(raw); // legitimate rotation
    expect(first.ok).toBe(true);
    if (!first.ok) throw new Error('unreachable');

    await rotateRefreshToken(raw); // attacker replays the OLD token -> reuse detected

    // The token issued by the legitimate rotation must now ALSO be dead,
    // because reuse detection revokes the whole device, not just the reused token.
    const thirdAttempt = await rotateRefreshToken(first.refreshToken);
    expect(thirdAttempt.ok).toBe(false);
  });

  it('SECURITY REGRESSION: revoking a device immediately invalidates its refresh token', async () => {
    const raw = await issueRefreshToken(userId, deviceId);
    await revokeDevice(deviceId, userId);
    const result = await rotateRefreshToken(raw);
    expect(result.ok).toBe(false);
    if (!result.ok) expect(result.reason).toBe('device_revoked');
  });

  it('rejects an unknown/invalid refresh token', async () => {
    const result = await rotateRefreshToken('not-a-real-token');
    expect(result.ok).toBe(false);
    if (!result.ok) expect(result.reason).toBe('invalid');
  });
});
