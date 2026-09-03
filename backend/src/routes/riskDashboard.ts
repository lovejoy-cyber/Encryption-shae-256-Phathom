import type { FastifyInstance } from 'fastify';
import { z } from 'zod';
import { requirePermission } from '../auth/authPlugin.js';

const ML_SERVICE_URL = process.env.ML_SERVICE_URL ?? 'http://localhost:8001';

/** Thin authenticated proxy in front of the ml-service (which has no auth of its own — it's internal-network-only, docs/ARCHITECTURE.md §1). */
export async function riskDashboardRoutes(app: FastifyInstance) {
  app.get('/orgs/:orgId/risk-dashboard', { preHandler: requirePermission('risk_dashboard:view') }, async (req, reply) => {
    const params = z.object({ orgId: z.string().uuid() }).parse(req.params);
    try {
      const res = await fetch(`${ML_SERVICE_URL}/orgs/${params.orgId}/investigations`);
      if (!res.ok) return reply.code(502).send({ error: 'ml_service_error' });
      return reply.send(await res.json());
    } catch {
      return reply.code(502).send({ error: 'ml_service_unreachable' });
    }
  });
}
