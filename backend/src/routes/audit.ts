import type { FastifyInstance } from 'fastify';
import { z } from 'zod';
import { eq, desc } from 'drizzle-orm';
import { db } from '../db/client.js';
import { auditLog } from '../db/schema.js';
import { requirePermission } from '../auth/authPlugin.js';
import { verifyChain } from '../audit/auditLog.js';

export async function auditRoutes(app: FastifyInstance) {
  app.get('/orgs/:orgId/audit-log', { preHandler: requirePermission('org:view_audit_log') }, async (req, reply) => {
    const params = z.object({ orgId: z.string().uuid() }).parse(req.params);
    const query = z.object({ limit: z.coerce.number().int().min(1).max(500).default(100) }).parse(req.query);
    const rows = await db.select().from(auditLog).where(eq(auditLog.orgId, params.orgId)).orderBy(desc(auditLog.id)).limit(query.limit);
    return reply.send(rows);
  });

  app.get('/orgs/:orgId/audit-log/verify', { preHandler: requirePermission('org:view_audit_log') }, async (_req, reply) => {
    // NOTE: verifies the GLOBAL chain (audit rows span all orgs in one append-only
    // sequence by design — see docs/ARCHITECTURE.md §5.5); org-scoping is a read filter, not a separate chain.
    const result = await verifyChain();
    return reply.send(result);
  });
}
