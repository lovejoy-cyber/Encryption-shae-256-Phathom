import { pathToFileURL } from 'node:url';
import Fastify from 'fastify';
import cors from '@fastify/cors';
import helmet from '@fastify/helmet';
import rateLimit from '@fastify/rate-limit';
import { env } from './lib/env.js';
import { redis } from './lib/rateLimiter.js';
import { authPlugin } from './auth/authPlugin.js';
import { authRoutes } from './routes/auth.js';
import { capabilityRoutes } from './routes/capabilities.js';
import { orgRoutes } from './routes/org.js';
import { auditRoutes } from './routes/audit.js';
import { riskDashboardRoutes } from './routes/riskDashboard.js';
import { ensureBucket } from './lib/objectStorage.js';

export async function buildServer() {
  await ensureBucket();
  const app = Fastify({ logger: true, trustProxy: true });

  await app.register(helmet, { contentSecurityPolicy: false }); // API-only; CSP is the client app's concern
  await app.register(cors, { origin: env.NODE_ENV === 'production' ? false : true });
  await app.register(rateLimit, { global: true, max: 300, timeWindow: '1 minute', redis });
  await app.register(authPlugin);

  app.get('/health', async () => ({ status: 'ok' }));

  await app.register(authRoutes);
  await app.register(capabilityRoutes);
  await app.register(orgRoutes);
  await app.register(auditRoutes);
  await app.register(riskDashboardRoutes);

  return app;
}

// pathToFileURL, not string concatenation, so this comparison is correct on
// Windows too (backslash paths vs. file:// URLs otherwise never match).
if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  const app = await buildServer();
  await app.listen({ port: env.PORT, host: '0.0.0.0' });
}
