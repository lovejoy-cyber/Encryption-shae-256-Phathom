/**
 * End-to-end WebAuthn ceremony tests using a real FIDO2/CTAP authenticator
 * emulator (nid-webauthn-emulator, maintained by Nikkei for passkey E2E
 * testing) rather than hand-crafted fixtures — this exercises the actual
 * CBOR/COSE/attestation parsing path in @simplewebauthn/server, not a
 * mocked-away version of it.
 */
import { describe, it, expect, beforeEach, afterAll } from 'vitest';
import { WebAuthnEmulator } from 'nid-webauthn-emulator';
import { sql, db } from '../src/db/client.js';
import { users } from '../src/db/schema.js';
import * as webauthn from '../src/auth/webauthn.js';
import { resetDatabase } from './dbHelpers.js';

const rp: webauthn.RpConfig = { rpName: 'PhantomVault Test', rpID: 'localhost', origin: 'http://localhost:5173' };
const ORIGIN = 'http://localhost:5173';

let userId: string;

beforeEach(async () => {
  await resetDatabase();
  const [user] = await db.insert(users).values({ email: 'passkey-user@example.com' }).returning();
  userId = user.id;
});
afterAll(async () => sql.end());

describe('WebAuthn registration + authentication (real emulated authenticator)', () => {
  it('completes a full register -> login round trip', async () => {
    const emulator = new WebAuthnEmulator();

    const creationOptions = await webauthn.startRegistration(userId, 'passkey-user@example.com', rp);
    const creationCredential = emulator.createJSON(ORIGIN, creationOptions);
    const regResult = await webauthn.finishRegistration(userId, creationCredential, rp);
    expect(regResult.verified).toBe(true);

    const requestOptions = await webauthn.startAuthentication('passkey-user@example.com', rp);
    const assertionCredential = emulator.getJSON(ORIGIN, requestOptions);
    const authResult = await webauthn.finishAuthentication(assertionCredential, rp);

    expect(authResult.verified).toBe(true);
    expect(authResult.userId).toBe(userId);
  });

  it('SECURITY REGRESSION: a registration challenge cannot be replayed for a second registration', async () => {
    const emulator = new WebAuthnEmulator();
    const creationOptions = await webauthn.startRegistration(userId, 'passkey-user@example.com', rp);
    const credential = emulator.createJSON(ORIGIN, creationOptions);

    const first = await webauthn.finishRegistration(userId, credential, rp);
    expect(first.verified).toBe(true);

    // Same response replayed: the challenge was already consumed, so this must fail.
    await expect(webauthn.finishRegistration(userId, credential, rp)).rejects.toThrow();
  });

  it('SECURITY REGRESSION: authentication with an unregistered credential is rejected', async () => {
    const emulator = new WebAuthnEmulator();
    // Register against a DIFFERENT rpID than the one finishAuthentication will check,
    // simulating a credential our DB has never seen.
    const foreignOptions = await webauthn.startRegistration(userId, 'passkey-user@example.com', rp);
    const foreignCredential = emulator.createJSON(ORIGIN, foreignOptions);
    // Deliberately do NOT call finishRegistration — this credential is never stored.

    const requestOptions = await webauthn.startAuthentication('passkey-user@example.com', rp);
    // Forge an assertion response referencing the unregistered credential id.
    const assertion = emulator.getJSON(ORIGIN, { ...requestOptions, allowCredentials: [{ id: foreignCredential.id, type: 'public-key' }] });
    const result = await webauthn.finishAuthentication(assertion, rp);
    expect(result.verified).toBe(false);
  });

  it('SECURITY REGRESSION: the emulator (like a real browser) refuses to sign an assertion for a mismatched rpID/origin at all', async () => {
    // This is the browser/authenticator-layer half of phishing resistance:
    // a compliant client will not even construct a cross-origin assertion,
    // independent of anything our server does. Asserting this documents
    // that defense exists, before testing our own server-side check below.
    const emulator = new WebAuthnEmulator();
    const creationOptions = await webauthn.startRegistration(userId, 'passkey-user@example.com', rp);
    const credential = emulator.createJSON(ORIGIN, creationOptions);
    await webauthn.finishRegistration(userId, credential, rp);

    const requestOptions = await webauthn.startAuthentication('passkey-user@example.com', rp);
    expect(() => emulator.getJSON('https://evil-phishing-site.example', requestOptions)).toThrow(/Invalid rpId/);
  });

  it('SECURITY REGRESSION: our server rejects a valid assertion if OUR configured expectedOrigin does not match', async () => {
    // Tests the second, independent layer: our own verifyAuthenticationResponse
    // call's expectedOrigin pinning, isolated from the emulator's own behavior.
    const emulator = new WebAuthnEmulator();
    const creationOptions = await webauthn.startRegistration(userId, 'passkey-user@example.com', rp);
    const credential = emulator.createJSON(ORIGIN, creationOptions);
    const reg = await webauthn.finishRegistration(userId, credential, rp);
    expect(reg.verified).toBe(true);

    const requestOptions = await webauthn.startAuthentication('passkey-user@example.com', rp);
    const assertion = emulator.getJSON(ORIGIN, requestOptions); // signed correctly for ORIGIN

    // But our server is (mis)configured to expect a different origin than the
    // one actually used — verification must fail rather than trust the claim.
    const misconfiguredRp: webauthn.RpConfig = { ...rp, origin: 'https://not-the-real-origin.example' };
    const result = await webauthn.finishAuthentication(assertion, misconfiguredRp);
    expect(result.verified).toBe(false);
  });
});
