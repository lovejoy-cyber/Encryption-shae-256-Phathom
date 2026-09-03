import type { FastifyInstance, FastifyRequest, FastifyReply } from 'fastify';
import { eq } from 'drizzle-orm';
import fp from 'fastify-plugin';
import { verifyAccessToken } from './sessions.js';
import { db } from '../db/client.js';
import { orgMembers } from '../db/schema.js';
import { roleHasPermission, type Permission } from '../rbac/permissions.js';

declare module 'fastify' {
  interface FastifyRequest {
    user?: { userId: string; deviceId: string; orgId?: string; role?: string };
  }
}

export const authPlugin = fp(async (app: FastifyInstance) => {
  app.decorateRequest('user', undefined);

  app.addHook('onRequest', async (req: FastifyRequest) => {
    const header = req.headers.authorization;
    if (!header?.startsWith('Bearer ')) return;
    try {
      const claims = await verifyAccessToken(header.slice('Bearer '.length));
      req.user = { userId: claims.sub, deviceId: claims.deviceId, orgId: claims.orgId, role: claims.role };
    } catch {
      // Leave req.user undefined; requireAuth() below is what actually enforces presence.
    }
  });
});

export async function requireAuth(req: FastifyRequest, reply: FastifyReply) {
  if (!req.user) {
    reply.code(401).send({ error: 'authentication_required' });
    return reply;
  }
}

/** Re-derives the caller's role from the DB for the target org — never trusts the JWT's role claim for authorization decisions. */
export function requirePermission(permission: Permission) {
  return async (req: FastifyRequest, reply: FastifyReply) => {
    if (!req.user) return reply.code(401).send({ error: 'authentication_required' });

    const orgId = (req.params as { orgId?: string })?.orgId ?? req.user.orgId;
    if (!orgId) return reply.code(400).send({ error: 'org_id_required' });

    const [membership] = await db.select().from(orgMembers).where(eq(orgMembers.userId, req.user.userId));
    if (!membership || membership.orgId !== orgId || !roleHasPermission(membership.role, permission)) {
      return reply.code(403).send({ error: 'forbidden', permission });
    }
  };
}
