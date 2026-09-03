import { z } from 'zod';

const envSchema = z.object({
  DATABASE_URL: z.string().default('postgres://phantomvault:phantomvault@localhost:5432/phantomvault'),
  REDIS_URL: z.string().default('redis://localhost:6379'),
  PORT: z.coerce.number().default(3000),
  /**
   * Master key for at-rest encryption of TOTP secrets and K_cap values
   * (src/lib/secretsAtRest.ts). 32 bytes, base64-encoded.
   *
   * DEV-ONLY DEFAULT BELOW. In any real deployment this MUST come from a
   * proper secret store (Docker/Compose secret, Vault, cloud KMS) — never
   * committed, never a fallback constant. We fail loudly in production
   * mode if the default is still in use.
   */
  MASTER_KEY_B64: z.string().default('AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA='),
  JWT_PRIVATE_KEY_B64: z.string().optional(),
  JWT_PUBLIC_KEY_B64: z.string().optional(),
  NODE_ENV: z.enum(['development', 'test', 'production']).default('development'),
  S3_ENDPOINT: z.string().default('http://localhost:9000'),
  S3_ACCESS_KEY: z.string().default('phantomvault'),
  S3_SECRET_KEY: z.string().default('phantomvault-dev-only'),
});

export const env = envSchema.parse(process.env);

if (env.NODE_ENV === 'production' && env.MASTER_KEY_B64 === 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=') {
  throw new Error('MASTER_KEY_B64 must be set to a real secret in production — refusing to start with the dev default.');
}
