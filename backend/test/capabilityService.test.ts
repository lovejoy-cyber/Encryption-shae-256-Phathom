import { describe, it, expect, beforeEach, afterAll } from 'vitest';
import { sql, db } from '../src/db/client.js';
import { users } from '../src/db/schema.js';
import { createCapability, releaseCapability, revokeCapability } from '../src/capabilities/capabilityService.js';
import { getBlob, ensureBucket } from '../src/lib/objectStorage.js';
import { resetDatabase } from './dbHelpers.js';

let userId: string;

beforeEach(async () => {
  await ensureBucket();
  await resetDatabase();
  const [user] = await db.insert(users).values({ email: 'sender@example.com' }).returning();
  userId = user.id;
});
afterAll(async () => sql.end());

const plaintext = new TextEncoder().encode('this is the inner ciphertext, opaque to the server');

describe('capability-released content — the double-envelope design (ARCHITECTURE.md §5.2)', () => {
  it('creates a capability and releases it successfully with no policy set', async () => {
    const cap = await createCapability({ creatorUserId: userId, ciphertextInner: plaintext, policy: {} });
    const result = await releaseCapability(cap.id, userId);
    expect(result.ok).toBe(true);
    if (result.ok) expect(Buffer.from(result.ciphertextInner).equals(Buffer.from(plaintext))).toBe(true);
  });

  it('SECURITY REGRESSION: an expired capability is denied and returns zero key material', async () => {
    const cap = await createCapability({
      creatorUserId: userId,
      ciphertextInner: plaintext,
      policy: { expiresAt: new Date(Date.now() - 1000) },
    });
    const result = await releaseCapability(cap.id, userId);
    expect(result.ok).toBe(false);
    if (!result.ok) expect(result.reason).toBe('expired');
    expect(Object.keys(result)).not.toContain('ciphertextInner');
  });

  it('SECURITY REGRESSION: a revoked capability is denied even before any release', async () => {
    const cap = await createCapability({ creatorUserId: userId, ciphertextInner: plaintext, policy: {} });
    await revokeCapability(cap.id, userId);
    const result = await releaseCapability(cap.id, userId);
    expect(result.ok).toBe(false);
    if (!result.ok) expect(result.reason).toBe('revoked');
  });

  it('SECURITY REGRESSION: revoking AFTER a successful release blocks all future releases (future-only revocation, as documented)', async () => {
    const cap = await createCapability({ creatorUserId: userId, ciphertextInner: plaintext, policy: {} });
    const first = await releaseCapability(cap.id, userId);
    expect(first.ok).toBe(true);

    await revokeCapability(cap.id, userId);

    const second = await releaseCapability(cap.id, userId);
    expect(second.ok).toBe(false);
    if (!second.ok) expect(second.reason).toBe('revoked');
  });

  it('SECURITY REGRESSION: max-opens is enforced and auto-revokes on the final permitted open', async () => {
    const cap = await createCapability({ creatorUserId: userId, ciphertextInner: plaintext, policy: { maxOpens: 2 } });

    const first = await releaseCapability(cap.id, userId);
    const second = await releaseCapability(cap.id, userId);
    const third = await releaseCapability(cap.id, userId);

    expect(first.ok).toBe(true);
    expect(second.ok).toBe(true);
    expect(third.ok).toBe(false);
    if (!third.ok) expect(third.reason).toBe('max_opens_reached');
  });

  it('SECURITY REGRESSION: releasing a nonexistent capability ID fails closed, not open', async () => {
    const result = await releaseCapability('00000000-0000-0000-0000-000000000000', userId);
    expect(result.ok).toBe(false);
    if (!result.ok) expect(result.reason).toBe('not_found');
  });

  it('the outer ciphertext stored in object storage is never the plaintext (server holds no usable copy)', async () => {
    const cap = await createCapability({ creatorUserId: userId, ciphertextInner: plaintext, policy: {} });
    const [row] = await sql`select blob_key from capabilities where id = ${cap.id}`;
    const storedBytes = await getBlob(row.blob_key);
    expect(Buffer.from(storedBytes).includes(Buffer.from(plaintext))).toBe(false);
  });

  it('SECURITY: revoking a capability deletes the ciphertext blob too, not just the key gating it (defense in depth)', async () => {
    const cap = await createCapability({ creatorUserId: userId, ciphertextInner: plaintext, policy: {} });
    const [row] = await sql`select blob_key from capabilities where id = ${cap.id}`;
    await revokeCapability(cap.id, userId);
    await expect(getBlob(row.blob_key)).rejects.toThrow();
  });

  it('SECURITY: reaching max-opens deletes the ciphertext blob after the final permitted release', async () => {
    const cap = await createCapability({ creatorUserId: userId, ciphertextInner: plaintext, policy: { maxOpens: 1 } });
    const [row] = await sql`select blob_key from capabilities where id = ${cap.id}`;
    await releaseCapability(cap.id, userId);
    await expect(getBlob(row.blob_key)).rejects.toThrow();
  });

  it('concurrent release attempts against a maxOpens=1 capability: exactly one succeeds', async () => {
    const cap = await createCapability({ creatorUserId: userId, ciphertextInner: plaintext, policy: { maxOpens: 1 } });
    const results = await Promise.all(Array.from({ length: 5 }, () => releaseCapability(cap.id, userId)));
    const successCount = results.filter((r) => r.ok).length;
    expect(successCount).toBe(1);
  });
});
