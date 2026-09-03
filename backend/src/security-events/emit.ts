/**
 * Feeds the ML anomaly-detection service. Allow-listed fields only —
 * THREAT_MODEL.md §4.6: never content, plaintext, or raw credentials.
 */
import { db, type Database } from '../db/client.js';
import { securityEvents } from '../db/schema.js';

export interface SecurityEventInput {
  userId?: string | null;
  orgId?: string | null;
  eventType: string;
  success?: boolean | null;
  ipAsn?: string | null;
  ipCountry?: string | null;
  deviceFingerprint?: string | null;
}

export async function emitSecurityEvent(input: SecurityEventInput, database: Database = db): Promise<void> {
  await database.insert(securityEvents).values({
    userId: input.userId ?? null,
    orgId: input.orgId ?? null,
    eventType: input.eventType,
    success: input.success ?? null,
    ipAsn: input.ipAsn ?? null,
    ipCountry: input.ipCountry ?? null,
    deviceFingerprint: input.deviceFingerprint ?? null,
  });
}
