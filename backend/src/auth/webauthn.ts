/**
 * WebAuthn passkey registration & authentication — the primary,
 * phishing-resistant auth factor (THREAT_MODEL.md §4.1). We delegate all
 * ceremony verification to @simplewebauthn/server rather than implementing
 * COSE/CBOR/attestation parsing ourselves.
 */
import { eq, and, gt } from 'drizzle-orm';
import {
  generateRegistrationOptions,
  verifyRegistrationResponse,
  generateAuthenticationOptions,
  verifyAuthenticationResponse,
  type VerifiedRegistrationResponse,
  type VerifiedAuthenticationResponse,
} from '@simplewebauthn/server';
import type {
  RegistrationResponseJSON,
  AuthenticationResponseJSON,
  PublicKeyCredentialCreationOptionsJSON,
  PublicKeyCredentialRequestOptionsJSON,
} from '@simplewebauthn/server';
import { db, type Database } from '../db/client.js';
import { users, webauthnCredentials, webauthnChallenges } from '../db/schema.js';
import { appendAuditEvent } from '../audit/auditLog.js';

export interface RpConfig {
  rpName: string;
  rpID: string;
  origin: string | string[];
}

const CHALLENGE_TTL_MS = 5 * 60 * 1000;

export async function startRegistration(userId: string, email: string, rp: RpConfig, database: Database = db): Promise<PublicKeyCredentialCreationOptionsJSON> {
  const existing = await database.select({ credentialId: webauthnCredentials.credentialId, transports: webauthnCredentials.transports })
    .from(webauthnCredentials).where(eq(webauthnCredentials.userId, userId));

  const options = await generateRegistrationOptions({
    rpName: rp.rpName,
    rpID: rp.rpID,
    userName: email,
    userID: new TextEncoder().encode(userId),
    attestationType: 'none',
    excludeCredentials: existing.map((c) => ({
      id: c.credentialId,
      transports: c.transports ? (c.transports.split(',') as never) : undefined,
    })),
    authenticatorSelection: { residentKey: 'preferred', userVerification: 'preferred' },
  });

  await database.insert(webauthnChallenges).values({
    userId,
    challenge: options.challenge,
    purpose: 'register',
    expiresAt: new Date(Date.now() + CHALLENGE_TTL_MS),
  });

  return options;
}

async function consumeChallenge(userId: string | null, purpose: 'register' | 'login', database: Database): Promise<string> {
  const conditions = [eq(webauthnChallenges.purpose, purpose), gt(webauthnChallenges.expiresAt, new Date())];
  if (userId) conditions.push(eq(webauthnChallenges.userId, userId));

  const [row] = await database.select().from(webauthnChallenges).where(and(...conditions)).orderBy(webauthnChallenges.id);
  if (!row) throw new Error('No valid challenge found (expired or never issued)');
  await database.delete(webauthnChallenges).where(eq(webauthnChallenges.id, row.id));
  return row.challenge;
}

export async function finishRegistration(
  userId: string,
  response: RegistrationResponseJSON,
  rp: RpConfig,
  database: Database = db
): Promise<VerifiedRegistrationResponse> {
  const expectedChallenge = await consumeChallenge(userId, 'register', database);

  const verification = await verifyRegistrationResponse({
    response,
    expectedChallenge,
    expectedOrigin: rp.origin,
    expectedRPID: rp.rpID,
  });

  if (verification.verified && verification.registrationInfo) {
    const { credential, credentialDeviceType, credentialBackedUp } = verification.registrationInfo;
    await database.insert(webauthnCredentials).values({
      credentialId: credential.id,
      userId,
      publicKey: Buffer.from(credential.publicKey).toString('base64'),
      counter: credential.counter,
      deviceType: credentialDeviceType,
      backedUp: credentialBackedUp,
      transports: credential.transports?.join(',') ?? null,
    });
    await appendAuditEvent({ actorUserId: userId, eventType: 'webauthn_credential_registered', eventData: { credentialId: credential.id } }, database);
  }

  return verification;
}

export async function startAuthentication(email: string | null, rp: RpConfig, database: Database = db): Promise<PublicKeyCredentialRequestOptionsJSON> {
  let allowCredentials: { id: string; transports?: never }[] | undefined;
  let userId: string | null = null;

  if (email) {
    const [user] = await database.select().from(users).where(eq(users.email, email));
    if (user) {
      userId = user.id;
      const creds = await database.select().from(webauthnCredentials).where(eq(webauthnCredentials.userId, user.id));
      allowCredentials = creds.map((c) => ({ id: c.credentialId, transports: c.transports ? (c.transports.split(',') as never) : undefined }));
    }
  }

  const options = await generateAuthenticationOptions({
    rpID: rp.rpID,
    allowCredentials,
    userVerification: 'preferred',
  });

  await database.insert(webauthnChallenges).values({
    userId,
    challenge: options.challenge,
    purpose: 'login',
    expiresAt: new Date(Date.now() + CHALLENGE_TTL_MS),
  });

  return options;
}

export interface AuthenticationVerificationResult {
  verified: boolean;
  userId?: string;
}

export async function finishAuthentication(
  response: AuthenticationResponseJSON,
  rp: RpConfig,
  database: Database = db
): Promise<AuthenticationVerificationResult> {
  const [credRow] = await database.select().from(webauthnCredentials).where(eq(webauthnCredentials.credentialId, response.id));
  if (!credRow) return { verified: false };

  const expectedChallenge = await consumeChallenge(null, 'login', database);

  let verification: VerifiedAuthenticationResponse;
  try {
    verification = await verifyAuthenticationResponse({
      response,
      expectedChallenge,
      expectedOrigin: rp.origin,
      expectedRPID: rp.rpID,
      credential: {
        id: credRow.credentialId,
        publicKey: new Uint8Array(Buffer.from(credRow.publicKey, 'base64')),
        counter: credRow.counter,
        transports: credRow.transports ? (credRow.transports.split(',') as never) : undefined,
      },
    });
  } catch {
    return { verified: false };
  }

  if (!verification.verified) return { verified: false };

  // Signature-counter regression is the standard signal an authenticator was cloned.
  if (verification.authenticationInfo.newCounter !== 0 && verification.authenticationInfo.newCounter <= credRow.counter) {
    await appendAuditEvent({
      actorUserId: credRow.userId,
      eventType: 'webauthn_counter_regression_detected',
      eventData: { credentialId: credRow.credentialId, storedCounter: credRow.counter, receivedCounter: verification.authenticationInfo.newCounter },
    }, database);
    return { verified: false };
  }

  await database.update(webauthnCredentials)
    .set({ counter: verification.authenticationInfo.newCounter, lastUsedAt: new Date() })
    .where(eq(webauthnCredentials.credentialId, credRow.credentialId));

  await appendAuditEvent({ actorUserId: credRow.userId, eventType: 'webauthn_login_success', eventData: { credentialId: credRow.credentialId } }, database);

  return { verified: true, userId: credRow.userId };
}
