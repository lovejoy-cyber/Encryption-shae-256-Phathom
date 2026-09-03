/**
 * B2B "zero-knowledge client handshake" portal.
 *
 * A firm (lawyer, accountant, consultant) creates an encrypted share for a
 * client; the client must pass a password check — optionally gated behind
 * a real WebAuthn platform biometric (Face ID / Windows Hello / fingerprint)
 * — before the file decrypts in their browser. Every share creation and
 * access is written to the SOC log with a timestamp.
 *
 * This module is demo/local-storage grade: it proves the handshake and
 * biometric gate work end-to-end in one browser. A real multi-tenant SaaS
 * needs a server: verify WebAuthn attestation server-side, store the
 * ciphertext + public key off the client device, and serve it over a
 * proper registered origin. See README.md roadmap for the Cloudflare
 * Workers + Durable Objects backend that upgrades this to production.
 */

import { get, set } from "idb-keyval";
import { encryptBytes, decryptBytes } from "./crypto";
import { logEvent } from "./soc";

export interface ShareRecord {
  id: string;
  name: string;
  type: string;
  size: number;
  createdAt: number;
  requireBiometric: boolean;
  credentialId?: string;
  envelope: Uint8Array;
}

export type ShareMeta = Omit<ShareRecord, "envelope">;

const shareKey = (id: string) => `pv-b2b-share:${id}`;
const INDEX_KEY = "pv-b2b-index";

function bufToBase64Url(buf: ArrayBuffer): string {
  const bytes = new Uint8Array(buf);
  let bin = "";
  for (const b of bytes) bin += String.fromCharCode(b);
  return btoa(bin).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

function base64UrlToBuf(b64url: string): ArrayBuffer {
  const b64 = b64url.replace(/-/g, "+").replace(/_/g, "/").padEnd(Math.ceil(b64url.length / 4) * 4, "=");
  const bin = atob(b64);
  const bytes = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) bytes[i] = bin.charCodeAt(i);
  return bytes.buffer;
}

export function isBiometricAvailable(): boolean {
  return typeof window !== "undefined" && !!window.PublicKeyCredential;
}

export async function createShare(file: File, password: string, requireBiometric: boolean): Promise<ShareMeta> {
  const bytes = new Uint8Array(await file.arrayBuffer());
  const envelope = await encryptBytes(bytes, password);
  const id = crypto.randomUUID();
  const record: ShareRecord = {
    id,
    name: file.name,
    type: file.type,
    size: file.size,
    createdAt: Date.now(),
    requireBiometric,
    envelope,
  };
  await set(shareKey(id), record);
  const index: string[] = (await get(INDEX_KEY)) ?? [];
  index.push(id);
  await set(INDEX_KEY, index);
  await logEvent({ type: "b2b_file_shared", severity: "info", detail: file.name });
  const { envelope: _e, ...meta } = record;
  return meta;
}

export async function listShares(): Promise<ShareMeta[]> {
  const index: string[] = (await get(INDEX_KEY)) ?? [];
  const out: ShareMeta[] = [];
  for (const id of index) {
    const rec = (await get(shareKey(id))) as ShareRecord | undefined;
    if (rec) {
      const { envelope: _e, ...meta } = rec;
      out.push(meta);
    }
  }
  return out.sort((a, b) => b.createdAt - a.createdAt);
}

/**
 * Registers a WebAuthn platform authenticator as the biometric gate.
 * Demo-grade: stores only the credential ID client-side with no
 * attestation verification — production must verify server-side.
 */
export async function registerBiometric(shareId: string, rpName = "PhantomVault"): Promise<void> {
  if (!isBiometricAvailable()) throw new Error("WebAuthn is not available in this browser");
  const challenge = crypto.getRandomValues(new Uint8Array(32));
  const credential = (await navigator.credentials.create({
    publicKey: {
      challenge,
      rp: { name: rpName },
      user: {
        id: crypto.getRandomValues(new Uint8Array(16)),
        name: shareId,
        displayName: `Share ${shareId.slice(0, 8)}`,
      },
      pubKeyCredParams: [
        { type: "public-key", alg: -7 },
        { type: "public-key", alg: -257 },
      ],
      authenticatorSelection: { authenticatorAttachment: "platform", userVerification: "required" },
      timeout: 60000,
    },
  })) as PublicKeyCredential | null;
  if (!credential) throw new Error("Biometric registration was cancelled");

  const record = (await get(shareKey(shareId))) as ShareRecord | undefined;
  if (!record) throw new Error("Share not found");
  record.credentialId = bufToBase64Url(credential.rawId);
  await set(shareKey(shareId), record);
}

export async function verifyBiometric(shareId: string): Promise<boolean> {
  const record = (await get(shareKey(shareId))) as ShareRecord | undefined;
  if (!record?.credentialId) return false;
  const challenge = crypto.getRandomValues(new Uint8Array(32));
  const assertion = await navigator.credentials.get({
    publicKey: {
      challenge,
      allowCredentials: [{ id: base64UrlToBuf(record.credentialId), type: "public-key" }],
      userVerification: "required",
      timeout: 60000,
    },
  });
  return assertion !== null;
}

export async function accessShare(
  shareId: string,
  password: string
): Promise<{ meta: ShareMeta; bytes: Uint8Array }> {
  const record = (await get(shareKey(shareId))) as ShareRecord | undefined;
  if (!record) throw new Error("Share not found");

  if (record.requireBiometric) {
    const verified = await verifyBiometric(shareId);
    if (!verified) throw new Error("Biometric verification failed or was cancelled");
  }

  const bytes = await decryptBytes(record.envelope, password);
  const { envelope: _e, ...meta } = record;
  await logEvent({ type: "b2b_file_accessed", severity: "info", detail: `${meta.name} accessed` });
  return { meta, bytes };
}
