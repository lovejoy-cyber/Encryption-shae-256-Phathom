/**
 * Capability-released content service — the double-envelope design in
 * docs/ARCHITECTURE.md §5.2. The server never sees plaintext or the CEK
 * (inner layer, sender/recipient shared secret); it generates and holds
 * K_cap (outer layer), which is what makes server-side expiry/revocation
 * a real cryptographic property rather than a UI-level promise.
 *
 * Callers pass `ciphertextInner` already encrypted client-side — this
 * module treats it as opaque bytes and only ever adds/removes the outer
 * layer. The outer-enveloped blob lives in object storage (MinIO/S3), not
 * inline in Postgres — this is what makes "encrypted media sharing"
 * (photos, files, not just short text) a real, size-scalable feature
 * rather than something that only works for small payloads.
 */
import { eq } from 'drizzle-orm';
import { encryptWithKey, decryptWithKey, generateKey } from '@phantomvault/crypto-core';
import { db, type Database } from '../db/client.js';
import { capabilities } from '../db/schema.js';
import { encryptAtRest, decryptAtRest } from '../lib/secretsAtRest.js';
import { appendAuditEvent } from '../audit/auditLog.js';
import { putBlob, getBlob, deleteBlob } from '../lib/objectStorage.js';

export interface CapabilityPolicy {
  expiresAt?: Date | null;
  maxOpens?: number | null;
}

export interface CreateCapabilityInput {
  creatorUserId: string;
  orgId?: string | null;
  ciphertextInner: Uint8Array;
  policy: CapabilityPolicy;
}

export interface CreatedCapability {
  id: string;
  createdAt: Date;
}

/** AAD binds the outer ciphertext to its own capability ID, so a ciphertext blob cannot be replayed under a different capability record. */
function aadFor(capabilityId: string): Uint8Array {
  return new TextEncoder().encode(`phantomvault-capability:${capabilityId}`);
}

function blobKeyFor(capabilityId: string): string {
  return `capabilities/${capabilityId}`;
}

export async function createCapability(input: CreateCapabilityInput, database: Database = db): Promise<CreatedCapability> {
  const kCap = await generateKey();

  // Insert first to get a DB-assigned id, then encrypt-outer bound to that id via AAD,
  // then upload. Two-step because AAD needs the id to exist first.
  const [row] = await database
    .insert(capabilities)
    .values({
      creatorUserId: input.creatorUserId,
      orgId: input.orgId ?? null,
      blobKey: '', // filled below, once we know the id
      kCapEncrypted: await encryptAtRest(kCap),
      expiresAt: input.policy.expiresAt ?? null,
      maxOpens: input.policy.maxOpens ?? null,
    })
    .returning();

  const ciphertextOuter = await encryptWithKey(input.ciphertextInner, kCap, aadFor(row.id));
  const blobKey = blobKeyFor(row.id);
  await putBlob(blobKey, ciphertextOuter);
  await database.update(capabilities).set({ blobKey }).where(eq(capabilities.id, row.id));

  await appendAuditEvent({
    actorUserId: input.creatorUserId,
    orgId: input.orgId ?? null,
    eventType: 'capability_created',
    eventData: {
      capabilityId: row.id,
      sizeBytes: input.ciphertextInner.length,
      hasExpiry: !!input.policy.expiresAt,
      maxOpens: input.policy.maxOpens ?? null,
    },
  }, database);

  return { id: row.id, createdAt: row.createdAt };
}

export type ReleaseFailureReason = 'not_found' | 'expired' | 'revoked' | 'max_opens_reached';

export type ReleaseResult =
  | { ok: true; ciphertextInner: Uint8Array }
  | { ok: false; reason: ReleaseFailureReason };

/**
 * The single code path that gates access to K_cap. Every denial reason is
 * audit-logged with zero key material returned — see THREAT_MODEL.md §9
 * "capability revocation" regression tests, which assert directly against
 * this function's negative cases.
 */
export async function releaseCapability(capabilityId: string, requesterUserId: string, database: Database = db): Promise<ReleaseResult> {
  const result = await database.transaction(async (tx) => {
    const [row] = await tx.select().from(capabilities).where(eq(capabilities.id, capabilityId)).for('update');

    const deny = async (reason: ReleaseFailureReason) => {
      await appendAuditEvent({
        actorUserId: requesterUserId,
        orgId: row?.orgId ?? null,
        eventType: 'capability_release_denied',
        eventData: { capabilityId, reason },
      }, tx as unknown as Database);
      return { ok: false as const, reason };
    };

    if (!row) return deny('not_found');
    if (row.expiresAt && row.expiresAt.getTime() < Date.now()) return deny('expired');
    // Checked before the generic `revoked` flag: releaseCapability() itself sets
    // revoked=true once maxOpens is reached (see below), so without this ordering
    // that more specific, more actionable reason would be masked by 'revoked' on
    // any attempt after the limit — this keeps the two causes distinguishable.
    if (row.maxOpens !== null && row.openCount >= row.maxOpens) return deny('max_opens_reached');
    if (row.revoked) return deny('revoked');

    const newOpenCount = row.openCount + 1;
    const willAutoRevoke = row.maxOpens !== null && newOpenCount >= row.maxOpens;
    await tx.update(capabilities).set({
      openCount: newOpenCount,
      revoked: willAutoRevoke,
      revokedAt: willAutoRevoke ? new Date() : row.revokedAt,
    }).where(eq(capabilities.id, capabilityId));

    const kCap = await decryptAtRest(row.kCapEncrypted);
    const ciphertextOuter = await getBlob(row.blobKey);
    const ciphertextInner = await decryptWithKey(ciphertextOuter, kCap, aadFor(capabilityId));

    await appendAuditEvent({
      actorUserId: requesterUserId,
      orgId: row.orgId,
      eventType: 'capability_released',
      eventData: { capabilityId, openCount: newOpenCount, autoRevoked: willAutoRevoke },
    }, tx as unknown as Database);

    return { ok: true as const, ciphertextInner, autoRevoked: willAutoRevoke, blobKey: row.blobKey };
  });

  // Defense in depth, done outside the transaction (object storage has no
  // transactional rollback with Postgres): once the final permitted open has
  // happened, delete the ciphertext blob too, not just the K_cap gate — so
  // even a future K_cap compromise recovers nothing.
  if (result.ok && result.autoRevoked) {
    await deleteBlob(result.blobKey).catch(() => {});
  }

  return result;
}

export async function revokeCapability(capabilityId: string, actorUserId: string, database: Database = db): Promise<void> {
  const blobKey = await database.transaction(async (tx) => {
    const [row] = await tx.select().from(capabilities).where(eq(capabilities.id, capabilityId)).for('update');
    if (!row) throw new Error('Capability not found');

    await tx.update(capabilities).set({ revoked: true, revokedAt: new Date() }).where(eq(capabilities.id, capabilityId));

    await appendAuditEvent({
      actorUserId,
      orgId: row.orgId,
      eventType: 'capability_revoked',
      eventData: { capabilityId },
    }, tx as unknown as Database);

    return row.blobKey;
  });

  // Same defense-in-depth as the auto-revoke path above: an explicit revoke
  // also deletes the ciphertext, not just the key gating it.
  await deleteBlob(blobKey).catch(() => {});
}
