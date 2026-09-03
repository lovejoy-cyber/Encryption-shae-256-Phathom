import type { FastifyInstance } from 'fastify';
import { z } from 'zod';
import { eq } from 'drizzle-orm';
import { createCapability, releaseCapability, revokeCapability } from '../capabilities/capabilityService.js';
import { requireAuth } from '../auth/authPlugin.js';
import { checkRateLimit } from '../lib/rateLimiter.js';
import { db } from '../db/client.js';
import { capabilities, orgMembers } from '../db/schema.js';
import { roleHasPermission } from '../rbac/permissions.js';

const RELEASE_REASON_STATUS: Record<string, number> = {
  not_found: 404,
  expired: 410,
  revoked: 410,
  max_opens_reached: 410,
};

export async function capabilityRoutes(app: FastifyInstance) {
  app.post('/capabilities', { preHandler: requireAuth }, async (req, reply) => {
    const body = z.object({
      ciphertextInner: z.string(), // base64
      orgId: z.string().uuid().optional(),
      expiresAt: z.string().datetime().optional(),
      maxOpens: z.number().int().positive().optional(),
    }).parse(req.body);

    const rl = await checkRateLimit(`capability_create:${req.user!.userId}`, 30, 60);
    if (!rl.allowed) return reply.code(429).send({ error: 'rate_limited' });

    const capability = await createCapability({
      creatorUserId: req.user!.userId,
      orgId: body.orgId,
      ciphertextInner: Buffer.from(body.ciphertextInner, 'base64'),
      policy: { expiresAt: body.expiresAt ? new Date(body.expiresAt) : null, maxOpens: body.maxOpens ?? null },
    });

    return reply.code(201).send(capability);
  });

  app.post('/capabilities/:id/release', { preHandler: requireAuth }, async (req, reply) => {
    const params = z.object({ id: z.string().uuid() }).parse(req.params);

    const rl = await checkRateLimit(`capability_release:${req.user!.userId}`, 60, 60);
    if (!rl.allowed) return reply.code(429).send({ error: 'rate_limited' });

    const result = await releaseCapability(params.id, req.user!.userId);
    if (!result.ok) {
      return reply.code(RELEASE_REASON_STATUS[result.reason] ?? 400).send({ error: result.reason });
    }
    return reply.send({ ciphertextInner: Buffer.from(result.ciphertextInner).toString('base64') });
  });

  app.post('/capabilities/:id/revoke', { preHandler: requireAuth }, async (req, reply) => {
    const params = z.object({ id: z.string().uuid() }).parse(req.params);

    const [row] = await db.select().from(capabilities).where(eq(capabilities.id, params.id));
    if (!row) return reply.code(404).send({ error: 'not_found' });

    const isOwner = row.creatorUserId === req.user!.userId;
    let hasOrgOverride = false;
    if (!isOwner && row.orgId) {
      const [membership] = await db.select().from(orgMembers).where(eq(orgMembers.userId, req.user!.userId));
      hasOrgOverride = !!membership && membership.orgId === row.orgId && roleHasPermission(membership.role, 'capability:revoke_any');
    }
    if (!isOwner && !hasOrgOverride) return reply.code(403).send({ error: 'forbidden' });

    await revokeCapability(params.id, req.user!.userId);
    return reply.send({ revoked: true });
  });
}
