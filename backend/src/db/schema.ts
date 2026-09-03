import {
  pgTable, uuid, text, timestamp, boolean, integer, bigserial, jsonb, primaryKey, index,
} from 'drizzle-orm/pg-core';

// Binary fields (public keys, encrypted secrets) are stored as base64 `text` rather than
// `bytea` — keeps the schema driver-agnostic and avoids encoding surprises across drivers.

export const users = pgTable('users', {
  id: uuid('id').primaryKey().defaultRandom(),
  email: text('email').notNull().unique(),
  createdAt: timestamp('created_at', { withTimezone: true }).notNull().defaultNow(),
  totpSecretEncrypted: text('totp_secret_encrypted'), // base64 key-envelope, see src/lib/secretsAtRest.ts
  totpEnabled: boolean('totp_enabled').notNull().default(false),
});

export const webauthnCredentials = pgTable('webauthn_credentials', {
  credentialId: text('credential_id').primaryKey(), // base64url
  userId: uuid('user_id').notNull().references(() => users.id, { onDelete: 'cascade' }),
  publicKey: text('public_key').notNull(), // base64
  counter: integer('counter').notNull().default(0),
  deviceType: text('device_type').notNull(),
  backedUp: boolean('backed_up').notNull().default(false),
  transports: text('transports'), // comma-separated
  createdAt: timestamp('created_at', { withTimezone: true }).notNull().defaultNow(),
  lastUsedAt: timestamp('last_used_at', { withTimezone: true }),
}, (t) => [index('webauthn_user_idx').on(t.userId)]);

export const webauthnChallenges = pgTable('webauthn_challenges', {
  id: uuid('id').primaryKey().defaultRandom(),
  userId: uuid('user_id').references(() => users.id, { onDelete: 'cascade' }),
  challenge: text('challenge').notNull(),
  purpose: text('purpose').notNull(), // 'register' | 'login'
  expiresAt: timestamp('expires_at', { withTimezone: true }).notNull(),
});

export const devices = pgTable('devices', {
  id: uuid('id').primaryKey().defaultRandom(),
  userId: uuid('user_id').notNull().references(() => users.id, { onDelete: 'cascade' }),
  name: text('name').notNull(),
  userAgent: text('user_agent'),
  firstSeen: timestamp('first_seen', { withTimezone: true }).notNull().defaultNow(),
  lastSeen: timestamp('last_seen', { withTimezone: true }).notNull().defaultNow(),
  revokedAt: timestamp('revoked_at', { withTimezone: true }),
}, (t) => [index('devices_user_idx').on(t.userId)]);

export const refreshTokens = pgTable('refresh_tokens', {
  id: uuid('id').primaryKey().defaultRandom(),
  userId: uuid('user_id').notNull().references(() => users.id, { onDelete: 'cascade' }),
  deviceId: uuid('device_id').notNull().references(() => devices.id, { onDelete: 'cascade' }),
  tokenHash: text('token_hash').notNull().unique(), // SHA-256 of the opaque token; raw value only ever sent to the client once
  expiresAt: timestamp('expires_at', { withTimezone: true }).notNull(),
  revokedAt: timestamp('revoked_at', { withTimezone: true }),
  replacedBy: uuid('replaced_by'),
  createdAt: timestamp('created_at', { withTimezone: true }).notNull().defaultNow(),
}, (t) => [index('refresh_user_idx').on(t.userId), index('refresh_device_idx').on(t.deviceId)]);

export const organizations = pgTable('organizations', {
  id: uuid('id').primaryKey().defaultRandom(),
  name: text('name').notNull(),
  createdAt: timestamp('created_at', { withTimezone: true }).notNull().defaultNow(),
});

export const ROLES = ['owner', 'admin', 'member', 'auditor'] as const;
export type Role = (typeof ROLES)[number];

export const orgMembers = pgTable('org_members', {
  orgId: uuid('org_id').notNull().references(() => organizations.id, { onDelete: 'cascade' }),
  userId: uuid('user_id').notNull().references(() => users.id, { onDelete: 'cascade' }),
  role: text('role').notNull().$type<Role>(),
  createdAt: timestamp('created_at', { withTimezone: true }).notNull().defaultNow(),
}, (t) => [primaryKey({ columns: [t.orgId, t.userId] })]);

/**
 * Capability-released content — the double-envelope design in
 * docs/ARCHITECTURE.md §5.2. `kCapEncrypted` is K_cap encrypted at rest
 * with the server master key (src/lib/secretsAtRest.ts); it is what makes
 * revocation real: deleting/withholding this row's usable K_cap makes the
 * associated blob permanently undecryptable, even to a party holding both
 * the outer ciphertext and the inner CEK.
 */
export const capabilities = pgTable('capabilities', {
  id: uuid('id').primaryKey().defaultRandom(),
  orgId: uuid('org_id').references(() => organizations.id, { onDelete: 'set null' }),
  creatorUserId: uuid('creator_user_id').notNull().references(() => users.id),
  blobKey: text('blob_key').notNull(), // object storage key for the outer ciphertext
  kCapEncrypted: text('k_cap_encrypted').notNull(),
  expiresAt: timestamp('expires_at', { withTimezone: true }),
  maxOpens: integer('max_opens'),
  openCount: integer('open_count').notNull().default(0),
  revoked: boolean('revoked').notNull().default(false),
  revokedAt: timestamp('revoked_at', { withTimezone: true }),
  createdAt: timestamp('created_at', { withTimezone: true }).notNull().defaultNow(),
}, (t) => [index('capabilities_creator_idx').on(t.creatorUserId)]);

/**
 * Tamper-evident audit log — hash chain per docs/ARCHITECTURE.md §5.5.
 * Application code must only ever INSERT here, never UPDATE/DELETE
 * (enforced by a DB trigger in the migration, not just convention).
 */
export const auditLog = pgTable('audit_log', {
  id: bigserial('id', { mode: 'number' }).primaryKey(),
  actorUserId: uuid('actor_user_id'),
  orgId: uuid('org_id'),
  eventType: text('event_type').notNull(),
  eventData: jsonb('event_data').notNull(),
  prevHash: text('prev_hash').notNull(),
  hash: text('hash').notNull(),
  createdAt: timestamp('created_at', { withTimezone: true }).notNull().defaultNow(),
});

/** Feature source for the ML anomaly-detection service — metadata only, never content. See THREAT_MODEL.md §4.6/§8. */
export const securityEvents = pgTable('security_events', {
  id: bigserial('id', { mode: 'number' }).primaryKey(),
  userId: uuid('user_id'),
  orgId: uuid('org_id'),
  eventType: text('event_type').notNull(),
  success: boolean('success'),
  ipAsn: text('ip_asn'),
  ipCountry: text('ip_country'),
  deviceFingerprint: text('device_fingerprint'),
  createdAt: timestamp('created_at', { withTimezone: true }).notNull().defaultNow(),
}, (t) => [index('security_events_user_idx').on(t.userId), index('security_events_created_idx').on(t.createdAt)]);
