/**
 * PhantomVault core cryptographic engine.
 *
 * Format (all binary, versioned so we can rotate parameters later):
 *   [1 byte version][16 bytes salt][12 bytes iv][ciphertext || 16-byte GCM tag]
 *
 * AES-256-GCM gives us confidentiality + integrity in one primitive.
 * PBKDF2-SHA256 at 600,000 iterations follows OWASP's 2023 minimum for
 * password-derived AES keys (raise ITERATIONS over time, never lower it).
 */

const VERSION = 1;
const SALT_LEN = 16;
const IV_LEN = 12;
const ITERATIONS = 600_000;
const KEY_LEN = 256;

export class DecryptionError extends Error {
  constructor(message = "Decryption failed: wrong password or corrupted data") {
    super(message);
    this.name = "DecryptionError";
  }
}

async function deriveKey(password: string, salt: Uint8Array): Promise<CryptoKey> {
  const enc = new TextEncoder();
  const baseKey = await crypto.subtle.importKey(
    "raw",
    enc.encode(password),
    "PBKDF2",
    false,
    ["deriveKey"]
  );
  return crypto.subtle.deriveKey(
    { name: "PBKDF2", salt: salt as BufferSource, iterations: ITERATIONS, hash: "SHA-256" },
    baseKey,
    { name: "AES-GCM", length: KEY_LEN },
    false,
    ["encrypt", "decrypt"]
  );
}

/** Encrypts arbitrary bytes with a password. Returns the versioned binary envelope. */
export async function encryptBytes(plaintext: Uint8Array, password: string): Promise<Uint8Array> {
  const salt = crypto.getRandomValues(new Uint8Array(SALT_LEN));
  const iv = crypto.getRandomValues(new Uint8Array(IV_LEN));
  const key = await deriveKey(password, salt);
  const ciphertext = new Uint8Array(
    await crypto.subtle.encrypt({ name: "AES-GCM", iv: iv as BufferSource }, key, plaintext as BufferSource)
  );

  const out = new Uint8Array(1 + SALT_LEN + IV_LEN + ciphertext.length);
  out[0] = VERSION;
  out.set(salt, 1);
  out.set(iv, 1 + SALT_LEN);
  out.set(ciphertext, 1 + SALT_LEN + IV_LEN);
  return out;
}

/** Decrypts a versioned binary envelope produced by encryptBytes. */
export async function decryptBytes(envelope: Uint8Array, password: string): Promise<Uint8Array> {
  if (envelope.length < 1 + SALT_LEN + IV_LEN + 16) {
    throw new DecryptionError("Payload too short to be valid");
  }
  const version = envelope[0];
  if (version !== VERSION) {
    throw new DecryptionError(`Unsupported payload version: ${version}`);
  }
  const salt = envelope.slice(1, 1 + SALT_LEN);
  const iv = envelope.slice(1 + SALT_LEN, 1 + SALT_LEN + IV_LEN);
  const ciphertext = envelope.slice(1 + SALT_LEN + IV_LEN);
  const key = await deriveKey(password, salt);

  try {
    const plaintext = await crypto.subtle.decrypt({ name: "AES-GCM", iv: iv as BufferSource }, key, ciphertext as BufferSource);
    return new Uint8Array(plaintext);
  } catch {
    throw new DecryptionError();
  }
}

// ---- Convenience wrappers for the text-messaging workflow ----

const B64_TABLE =
  "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

/** URL-safe-ish base64 for pasting ciphertext into chat apps. */
export function bytesToB64(bytes: Uint8Array): string {
  let binary = "";
  for (let i = 0; i < bytes.length; i++) binary += String.fromCharCode(bytes[i]);
  return btoa(binary);
}

export function b64ToBytes(b64: string): Uint8Array {
  const cleaned = b64.trim();
  for (const ch of cleaned) {
    if (!B64_TABLE.includes(ch) && ch !== "=") {
      throw new DecryptionError("Pasted text is not a valid PhantomVault payload");
    }
  }
  const binary = atob(cleaned);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) bytes[i] = binary.charCodeAt(i);
  return bytes;
}

const PV_PREFIX = "PV1:";

/** Encrypts a text message and returns a copy-pasteable ciphertext string. */
export async function encryptText(message: string, password: string): Promise<string> {
  const envelope = await encryptBytes(new TextEncoder().encode(message), password);
  return PV_PREFIX + bytesToB64(envelope);
}

/** Decrypts a ciphertext string produced by encryptText. */
export async function decryptText(payload: string, password: string): Promise<string> {
  const trimmed = payload.trim();
  if (!trimmed.startsWith(PV_PREFIX)) {
    throw new DecryptionError("This doesn't look like a PhantomVault message");
  }
  const envelope = b64ToBytes(trimmed.slice(PV_PREFIX.length));
  const plaintext = await decryptBytes(envelope, password);
  return new TextDecoder().decode(plaintext);
}

/** SHA-256 hash, used by the file scanner and SOC log for integrity fingerprints. */
export async function sha256Hex(data: Uint8Array): Promise<string> {
  const digest = await crypto.subtle.digest("SHA-256", data as BufferSource);
  return Array.from(new Uint8Array(digest))
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");
}
