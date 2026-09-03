import { WebAuthnEmulator } from 'nid-webauthn-emulator';

const BASE = 'http://localhost:3000';
const ORIGIN = 'http://localhost:5173';
const email = `smoketest+${Date.now()}@example.com`;

async function post(path, body, token) {
  const res = await fetch(BASE + path, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', ...(token ? { Authorization: `Bearer ${token}` } : {}) },
    body: JSON.stringify(body ?? {}),
  });
  const json = await res.json().catch(() => ({}));
  return { status: res.status, json };
}

const emulator = new WebAuthnEmulator();

console.log('--- register/start ---');
const startReg = await post('/auth/register/start', { email });
console.log(startReg.status);

console.log('--- emulator creates credential ---');
const cred = emulator.createJSON(ORIGIN, startReg.json);

console.log('--- register/finish ---');
const finishReg = await post('/auth/register/finish', { email, response: cred, deviceName: 'Smoke Test Device' });
console.log(finishReg.status, Object.keys(finishReg.json));
const { accessToken } = finishReg.json;

console.log('--- create org ---');
const org = await post('/orgs', { name: 'Smoke Test Org' }, accessToken);
console.log(org.status, org.json);

console.log('--- create capability ---');
const ciphertextInner = Buffer.from('this is opaque inner ciphertext').toString('base64');
const cap = await post('/capabilities', { ciphertextInner, orgId: org.json.id, maxOpens: 1 }, accessToken);
console.log(cap.status, cap.json);

console.log('--- release capability ---');
const release = await post(`/capabilities/${cap.json.id}/release`, {}, accessToken);
console.log(release.status, release.json);
console.log('decoded:', Buffer.from(release.json.ciphertextInner, 'base64').toString());

console.log('--- release again (should fail: max_opens_reached) ---');
const release2 = await post(`/capabilities/${cap.json.id}/release`, {}, accessToken);
console.log(release2.status, release2.json);

console.log('--- view audit log ---');
await post('/auth/totp/setup', {}, accessToken); // add a varied event type
const auditLog = await fetch(`${BASE}/orgs/${org.json.id}/audit-log`, { headers: { Authorization: `Bearer ${accessToken}` } });
console.log(auditLog.status, (await auditLog.json()).length, 'entries visible to owner');

console.log('--- verify chain ---');
const verify = await fetch(`${BASE}/orgs/${org.json.id}/audit-log/verify`, { headers: { Authorization: `Bearer ${accessToken}` } });
console.log(verify.status, await verify.json());

console.log('--- unauthenticated request is rejected ---');
const noAuth = await fetch(`${BASE}/orgs/${org.json.id}/audit-log`);
console.log(noAuth.status);

console.log('--- risk dashboard proxy (backend -> ml-service) ---');
const risk = await fetch(`${BASE}/orgs/${org.json.id}/risk-dashboard`, { headers: { Authorization: `Bearer ${accessToken}` } });
console.log(risk.status, await risk.json());
