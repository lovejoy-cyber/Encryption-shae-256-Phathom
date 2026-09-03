import { describe, it, expect, beforeEach, afterAll } from 'vitest';
import { generate as generateOtp } from 'otplib';
import { eq } from 'drizzle-orm';
import { sql, db } from '../src/db/client.js';
import { users } from '../src/db/schema.js';
import { setupTotp, confirmTotp, verifyTotp, isTotpEnabled } from '../src/auth/totp.js';
import { resetDatabase } from './dbHelpers.js';

let userId: string;

beforeEach(async () => {
  await resetDatabase();
  const [user] = await db.insert(users).values({ email: 'totp-user@example.com' }).returning();
  userId = user.id;
});
afterAll(async () => sql.end());

describe('TOTP MFA', () => {
  it('is not enabled until confirmTotp succeeds with a valid code', async () => {
    const { secret } = await setupTotp(userId, 'totp-user@example.com');
    expect(await isTotpEnabled(userId)).toBe(false);

    const code = await generateOtp({ secret });
    const confirmed = await confirmTotp(userId, code);
    expect(confirmed).toBe(true);
    expect(await isTotpEnabled(userId)).toBe(true);
  });

  it('SECURITY REGRESSION: confirmTotp rejects a wrong code and does not enable MFA', async () => {
    await setupTotp(userId, 'totp-user@example.com');
    const confirmed = await confirmTotp(userId, '000000');
    expect(confirmed).toBe(false);
    expect(await isTotpEnabled(userId)).toBe(false);
  });

  it('verifyTotp accepts a correct code after MFA is enabled', async () => {
    const { secret } = await setupTotp(userId, 'totp-user@example.com');
    await confirmTotp(userId, await generateOtp({ secret }));

    const code = await generateOtp({ secret });
    expect(await verifyTotp(userId, code)).toBe(true);
  });

  it('SECURITY REGRESSION: verifyTotp rejects a wrong code', async () => {
    const { secret } = await setupTotp(userId, 'totp-user@example.com');
    await confirmTotp(userId, await generateOtp({ secret }));

    expect(await verifyTotp(userId, '111111')).toBe(false);
  });

  it('SECURITY REGRESSION: verifyTotp fails closed for a user who never enabled MFA', async () => {
    expect(await verifyTotp(userId, '123456')).toBe(false);
  });

  it('the stored seed is encrypted at rest, not plaintext', async () => {
    await setupTotp(userId, 'totp-user@example.com');
    const [row] = await db.select({ totpSecretEncrypted: users.totpSecretEncrypted }).from(users).where(eq(users.id, userId));
    expect(row.totpSecretEncrypted).toBeTruthy();
    // A raw Base32 TOTP secret is short, uppercase-alnum; ciphertext should not resemble it at all.
    expect(row.totpSecretEncrypted).not.toMatch(/^[A-Z2-7]+=*$/);
  });
});
