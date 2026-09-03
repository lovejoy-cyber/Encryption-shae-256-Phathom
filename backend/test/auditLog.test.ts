import { describe, it, expect, beforeEach, afterAll } from 'vitest';
import { sql, db } from '../src/db/client.js';
import { auditLog } from '../src/db/schema.js';
import { appendAuditEvent, verifyChain, GENESIS_HASH } from '../src/audit/auditLog.js';
import { resetDatabase } from './dbHelpers.js';
import { eq } from 'drizzle-orm';

beforeEach(resetDatabase);
afterAll(async () => sql.end());

describe('tamper-evident audit log', () => {
  it('the first row chains from GENESIS_HASH', async () => {
    const row = await appendAuditEvent({ eventType: 'test_event', eventData: { n: 1 } });
    expect(row.prevHash).toBe(GENESIS_HASH);
  });

  it('each subsequent row chains from the previous row\'s hash', async () => {
    const a = await appendAuditEvent({ eventType: 'e1', eventData: {} });
    const b = await appendAuditEvent({ eventType: 'e2', eventData: {} });
    expect(b.prevHash).toBe(a.hash);
  });

  it('verifyChain reports valid for an untouched log', async () => {
    await appendAuditEvent({ eventType: 'e1', eventData: { a: 1 } });
    await appendAuditEvent({ eventType: 'e2', eventData: { b: 2 } });
    await appendAuditEvent({ eventType: 'e3', eventData: { c: 3 } });
    const result = await verifyChain();
    expect(result.valid).toBe(true);
    expect(result.totalRows).toBe(3);
  });

  it('detects tampering when a row\'s content is modified directly in the DB', async () => {
    await appendAuditEvent({ eventType: 'e1', eventData: {} });
    const target = await appendAuditEvent({ eventType: 'e2', eventData: { secret: 'original' } });
    await appendAuditEvent({ eventType: 'e3', eventData: {} });

    // Bypass the append-only trigger's UPDATE block using the same mechanism
    // a determined attacker with row-level write access would need: directly
    // disabling the trigger for this session. Proves verifyChain() catches
    // content tampering even when the DB-level guard is somehow defeated.
    await sql`ALTER TABLE audit_log DISABLE TRIGGER audit_log_no_update`;
    await db.update(auditLog).set({ eventData: { secret: 'tampered' } }).where(eq(auditLog.id, target.id));
    await sql`ALTER TABLE audit_log ENABLE TRIGGER audit_log_no_update`;

    const result = await verifyChain();
    expect(result.valid).toBe(false);
    expect(result.brokenAtId).toBe(target.id);
  });

  it('the append-only trigger blocks UPDATE at the database level', async () => {
    const row = await appendAuditEvent({ eventType: 'e1', eventData: {} });
    await expect(
      sql`UPDATE audit_log SET event_type = 'hacked' WHERE id = ${row.id}`
    ).rejects.toThrow(/append-only/);
  });

  it('the append-only trigger blocks DELETE at the database level', async () => {
    const row = await appendAuditEvent({ eventType: 'e1', eventData: {} });
    await expect(sql`DELETE FROM audit_log WHERE id = ${row.id}`).rejects.toThrow(/append-only/);
  });

  it('concurrent appends never fork the chain (advisory lock serializes them)', async () => {
    await Promise.all(Array.from({ length: 10 }, (_, i) => appendAuditEvent({ eventType: `concurrent_${i}`, eventData: { i } })));
    const result = await verifyChain();
    expect(result.valid).toBe(true);
    expect(result.totalRows).toBe(10);
  });
});
