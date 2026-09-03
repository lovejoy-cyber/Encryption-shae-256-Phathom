/**
 * Client for the PhantomVault backend (backend/, see docs/ARCHITECTURE.md).
 * This is what "Capability Mode" runs on — the server-mediated,
 * revocable-access path — as distinct from the fully local "Offline Mode"
 * that the rest of this app implements without any network dependency.
 *
 * Tokens are held in memory only (module-level state): simplest safe
 * default for a first pass — a reload requires logging in again. A
 * production build would move the refresh token to an httpOnly cookie
 * (the backend already has @fastify/cookie available for this) rather
 * than ever putting it somewhere JS-readable long-term.
 */
import { startRegistration, startAuthentication } from '@simplewebauthn/browser';
import { bytesToB64, b64ToBytes } from './crypto';

const BACKEND_URL = (import.meta as unknown as { env?: Record<string, string> }).env?.VITE_BACKEND_URL ?? 'http://localhost:3000';

let accessToken: string | null = null;
let refreshToken: string | null = null;
let currentEmail: string | null = null;

const listeners = new Set<() => void>();
function notify() {
  listeners.forEach((l) => l());
}
export function onConnectionChange(listener: () => void): () => void {
  listeners.add(listener);
  return () => listeners.delete(listener);
}

export function isConnected(): boolean {
  return accessToken !== null;
}
export function getCurrentEmail(): string | null {
  return currentEmail;
}

export class BackendError extends Error {
  status: number;
  code: string;
  constructor(status: number, code: string) {
    super(`Backend error ${status}: ${code}`);
    this.status = status;
    this.code = code;
  }
}

async function raw(path: string, options: RequestInit = {}): Promise<Response> {
  const headers = new Headers(options.headers);
  headers.set('Content-Type', 'application/json');
  if (accessToken) headers.set('Authorization', `Bearer ${accessToken}`);
  return fetch(`${BACKEND_URL}${path}`, { ...options, headers });
}

async function api<T>(path: string, options: RequestInit = {}, retried = false): Promise<T> {
  const res = await raw(path, options);
  if (res.status === 401 && !retried && refreshToken) {
    if (await tryRefresh()) return api<T>(path, options, true);
  }
  if (!res.ok) {
    const body = await res.json().catch(() => ({}));
    throw new BackendError(res.status, body.error ?? 'request_failed');
  }
  return res.json();
}

async function tryRefresh(): Promise<boolean> {
  if (!refreshToken) return false;
  try {
    const res = await fetch(`${BACKEND_URL}/auth/refresh`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ refreshToken }),
    });
    if (!res.ok) {
      clearSession();
      return false;
    }
    const json = await res.json();
    accessToken = json.accessToken;
    refreshToken = json.refreshToken;
    return true;
  } catch {
    return false;
  }
}

function clearSession() {
  accessToken = null;
  refreshToken = null;
  currentEmail = null;
  notify();
}

function setSession(email: string, result: { accessToken: string; refreshToken: string; deviceId: string }) {
  accessToken = result.accessToken;
  refreshToken = result.refreshToken;
  currentEmail = email;
  notify();
}

export async function register(email: string): Promise<void> {
  const optionsJSON = await api<import('@simplewebauthn/browser').PublicKeyCredentialCreationOptionsJSON>('/auth/register/start', {
    method: 'POST',
    body: JSON.stringify({ email }),
  });
  const response = await startRegistration({ optionsJSON });
  const result = await api<{ accessToken: string; refreshToken: string; deviceId: string }>('/auth/register/finish', {
    method: 'POST',
    body: JSON.stringify({ email, response, deviceName: shortDeviceName() }),
  });
  setSession(email, result);
}

export interface LoginResult {
  totpRequired: boolean;
  pendingToken?: string;
}

export async function login(email?: string): Promise<LoginResult> {
  const optionsJSON = await api<import('@simplewebauthn/browser').PublicKeyCredentialRequestOptionsJSON>('/auth/login/start', {
    method: 'POST',
    body: JSON.stringify({ email }),
  });
  const response = await startAuthentication({ optionsJSON });
  const result = await api<{ totpRequired?: boolean; pendingToken?: string; accessToken?: string; refreshToken?: string; deviceId?: string }>(
    '/auth/login/finish',
    { method: 'POST', body: JSON.stringify({ response, deviceName: shortDeviceName() }) }
  );
  if (result.totpRequired) return { totpRequired: true, pendingToken: result.pendingToken };
  setSession(email ?? '(passkey account)', result as { accessToken: string; refreshToken: string; deviceId: string });
  return { totpRequired: false };
}

export async function completeTotpLogin(email: string, pendingToken: string, code: string): Promise<void> {
  const result = await api<{ accessToken: string; refreshToken: string; deviceId: string }>('/auth/login/totp', {
    method: 'POST',
    body: JSON.stringify({ pendingToken, code }),
  });
  setSession(email, result);
}

export function logout(): void {
  clearSession();
}

function shortDeviceName(): string {
  return navigator.userAgent.slice(0, 60);
}

export interface CreateCapabilityParams {
  ciphertextInner: Uint8Array;
  orgId?: string;
  expiresAt?: Date | null;
  maxOpens?: number | null;
}

export async function createCapability(params: CreateCapabilityParams): Promise<{ id: string; createdAt: string }> {
  return api('/capabilities', {
    method: 'POST',
    body: JSON.stringify({
      ciphertextInner: bytesToB64(params.ciphertextInner),
      orgId: params.orgId,
      expiresAt: params.expiresAt ? params.expiresAt.toISOString() : undefined,
      maxOpens: params.maxOpens ?? undefined,
    }),
  });
}

export type CapabilityReleaseError = 'not_found' | 'expired' | 'revoked' | 'max_opens_reached' | 'other';

export async function releaseCapability(id: string): Promise<Uint8Array> {
  try {
    const result = await api<{ ciphertextInner: string }>(`/capabilities/${id}/release`, { method: 'POST', body: '{}' });
    return b64ToBytes(result.ciphertextInner);
  } catch (err) {
    if (err instanceof BackendError) {
      throw Object.assign(new Error(describeReleaseError(err.code as CapabilityReleaseError)), { code: err.code });
    }
    throw err;
  }
}

function describeReleaseError(code: string): string {
  switch (code) {
    case 'not_found':
      return "This capability doesn't exist (wrong ID, or it was never created).";
    case 'expired':
      return 'This capability has expired.';
    case 'revoked':
      return 'This capability has been revoked and can no longer be opened.';
    case 'max_opens_reached':
      return 'This capability has already been opened the maximum allowed number of times.';
    default:
      return 'Could not open this capability.';
  }
}

export async function revokeCapability(id: string): Promise<void> {
  await api(`/capabilities/${id}/revoke`, { method: 'POST', body: '{}' });
}
