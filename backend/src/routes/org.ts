import type { FastifyInstance } from 'fastify';
import { z } from 'zod';
import { eq, and } from 'drizzle-orm';
import { db } from '../db/client.js';
import { organizations, orgMembers, users, ROLES } from '../db/schema.js';
import { requireAuth, requirePermission } from '../auth/authPlugin.js';
import { appendAuditEvent } from '../audit/auditLog.js';

export async function orgRoutes(app: FastifyInstance) {
  app.post('/orgs', { preHandler: requireAuth }, async (req, reply) => {
    const body = z.object({ name: z.string().min(1).max(200) }).parse(req.body);
    const [org] = await db.insert(organizations).values({ name: body.name }).returning();
    await db.insert(orgMembers).values({ orgId: org.id, userId: req.user!.userId, role: 'owner' });
    await appendAuditEvent({ actorUserId: req.user!.userId, orgId: org.id, eventType: 'org_created', eventData: { name: body.name } });
    return reply.code(201).send(org);
  });

  app.get('/orgs/:orgId/members', { preHandler: requireAuth }, async (req, reply) => {
    const params = z.object({ orgId: z.string().uuid() }).parse(req.params);
    const [membership] = await db.select().from(orgMembers).where(and(eq(orgMembers.orgId, params.orgId), eq(orgMembers.userId, req.user!.userId)));
    if (!membership) return reply.code(403).send({ error: 'forbidden' });

    const rows = await db.select({ userId: orgMembers.userId, role: orgMembers.role, email: users.email })
      .from(orgMembers).innerJoin(users, eq(users.id, orgMembers.userId)).where(eq(orgMembers.orgId, params.orgId));
    return reply.send(rows);
  });

  app.post('/orgs/:orgId/members', { preHandler: requirePermission('org:manage_members') }, async (req, reply) => {
    const params = z.object({ orgId: z.string().uuid() }).parse(req.params);
    const body = z.object({ email: z.string().email(), role: z.enum(ROLES) }).parse(req.body);

    const [user] = await db.select().from(users).where(eq(users.email, body.email));
    if (!user) return reply.code(404).send({ error: 'user_not_found' });

    await db.insert(orgMembers).values({ orgId: params.orgId, userId: user.id, role: body.role })
      .onConflictDoUpdate({ target: [orgMembers.orgId, orgMembers.userId], set: { role: body.role } });

    await appendAuditEvent({ actorUserId: req.user!.userId, orgId: params.orgId, eventType: 'org_member_role_set', eventData: { targetUserId: user.id, role: body.role } });
    return reply.send({ ok: true });
  });

  app.post('/orgs/:orgId/members/:userId/remove', { preHandler: requirePermission('org:manage_members') }, async (req, reply) => {
    const params = z.object({ orgId: z.string().uuid(), userId: z.string().uuid() }).parse(req.params);
    await db.delete(orgMembers).where(and(eq(orgMembers.orgId, params.orgId), eq(orgMembers.userId, params.userId)));
    await appendAuditEvent({ actorUserId: req.user!.userId, orgId: params.orgId, eventType: 'org_member_removed', eventData: { targetUserId: params.userId } });
    return reply.send({ ok: true });
  });
}
