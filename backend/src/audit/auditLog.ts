/**
 * Tamper-evident audit log (docs/ARCHITECTURE.md §5.5, THREAT_MODEL.md §4.5).
 *
 * Each row commits to SHA-256(prev_hash || canonical_json(row content)).
 * `verifyChain()` re-walks the table and recomputes every hash — any
 * historical edit (including a direct DB UPDATE bypassing this module)
 * breaks the chain from that point forward and is detected, not silently
 * accepted. The append-only property (no UPDATE/DELETE) is additionally
 * enforced at the database level by a trigger — see
 * drizzle/0001_audit_log_append_only.sql — so this module's guarantee
 * does not rest on application code alone.
 */
import { asc, sql } from 'drizzle-orm';
import { sha256Hex } from '@phantomvault/crypto-core';
import { db, type Database } from '../db/client.js';
import { auditLog } from '../db/schema.js';

/** Arbitrary fixed lock key — scopes the advisory lock to "audit log appends" specifically. */
const AUDIT_APPEND_LOCK_KEY = 0x50485631; // 'PHV1' as an int, just needs to be a stable constant

export const GENESIS_HASH = '0'.repeat(64);

function sortKeysDeep(value: unknown): unknown {
  if (Array.isArray(value)) return value.map(sortKeysDeep);
  if (value && typeof value === 'object') {
    return Object.keys(value as Record<string, unknown>)
      .sort()
      .reduce((acc: Record<string, unknown>, k) => {
        acc[k] = sortKeysDeep((value as Record<string, unknown>)[k]);
        return acc;
      }, {});
  }
  return value;
}

function canonicalize(value: unknown): string {
  return JSON.stringify(sortKeysDeep(value));
}

interface ChainableRow {
  prevHash: string;
  actorUserId: string | null;
  orgId: string | null;
  eventType: string;
  eventData: Record<string, unknown>;
  createdAt: Date;
}

async function computeHash(row: ChainableRow): Promise<string> {
  const canonical = canonicalize({
    prevHash: row.prevHash,
    actorUserId: row.actorUserId,
    orgId: row.orgId,
    eventType: row.eventType,
    eventData: row.eventData,
    createdAt: row.createdAt.toISOString(),
  });
  return sha256Hex(new TextEncoder().encode(canonical));
}

export interface AuditEventInput {
  actorUserId?: string | null;
  orgId?: string | null;
  eventType: string;
  eventData: Record<string, unknown>;
}

export async function appendAuditEvent(input: AuditEventInput, database: Database = db) {
  return database.transaction(async (tx) => {
    // Advisory lock scoped to audit-log appends: guarantees a single writer
    // reads "the last row" and inserts the next one atomically, so two
    // concurrent appends can never both compute the same prevHash and fork
    // the chain. Released automatically at transaction end.
    await tx.execute(sql`select pg_advisory_xact_lock(${AUDIT_APPEND_LOCK_KEY})`);

    const [prevRow] = await tx.select({ hash: auditLog.hash }).from(auditLog).orderBy(sql`${auditLog.id} desc`).limit(1);
    const prevHash = prevRow?.hash ?? GENESIS_HASH;

    const row: ChainableRow = {
      prevHash,
      actorUserId: input.actorUserId ?? null,
      orgId: input.orgId ?? null,
      eventType: input.eventType,
      eventData: input.eventData,
      createdAt: new Date(),
    };
    const hash = await computeHash(row);

    const [inserted] = await tx
      .insert(auditLog)
      .values({ ...row, hash })
      .returning();
    return inserted;
  });
}

export interface ChainVerificationResult {
  valid: boolean;
  totalRows: number;
  brokenAtId?: number;
  reason?: string;
}

/** Independently re-walks the whole chain. Use this, not trust, to answer "has the log been tampered with." */
export async function verifyChain(database: Database = db): Promise<ChainVerificationResult> {
  const rows = await database.select().from(auditLog).orderBy(asc(auditLog.id));
  let expectedPrevHash = GENESIS_HASH;

  for (const row of rows) {
    if (row.prevHash !== expectedPrevHash) {
      return { valid: false, totalRows: rows.length, brokenAtId: row.id, reason: 'prev_hash does not match the actual previous row (chain fork or deleted row)' };
    }
    const recomputed = await computeHash({
      prevHash: row.prevHash,
      actorUserId: row.actorUserId,
      orgId: row.orgId,
      eventType: row.eventType,
      eventData: row.eventData as Record<string, unknown>,
      createdAt: row.createdAt,
    });
    if (recomputed !== row.hash) {
      return { valid: false, totalRows: rows.length, brokenAtId: row.id, reason: 'stored hash does not match recomputed hash (row content was modified)' };
    }
    expectedPrevHash = row.hash;
  }

  return { valid: true, totalRows: rows.length };
}
