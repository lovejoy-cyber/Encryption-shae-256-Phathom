/**
 * X25519 "sealed box" — anonymous public-key encryption (ECIES-style),
 * equivalent in construction to libsodium's crypto_box_seal. Used where
 * content should be encryptable to a recipient's known public key without
 * a pre-shared password (e.g. capability release targeting a specific
 * registered device/identity rather than an out-of-band shared secret).
 *
 * Construction: ephemeral X25519 keypair -> ECDH with recipient's public
 * key -> HKDF-SHA256 to derive an AES-256 key -> AES-256-GCM. The ephemeral
 * public key travels alongside the ciphertext (it's not secret); the
 * recipient redoes the ECDH with their secret key to recover the same
 * derived key. Forward secrecy per-message: the ephemeral secret is
 * discarded immediately after encryption and never stored.
 */

import { x25519 } from '@noble/curves/ed25519';
import { hkdf } from '@noble/hashes/hkdf';
import { sha256 } from '@noble/hashes/sha256';
import { aesGcmEncrypt, aesGcmDecrypt, DecryptionError, IV_LENGTH } from './primitives.js';
import { concatBytes } from './encoding.js';

const PUBLIC_KEY_LENGTH = 32;
const HKDF_INFO = new TextEncoder().encode('phantomvault-sealed-box-v1');

export interface X25519KeyPair {
  publicKey: Uint8Array;
  secretKey: Uint8Array;
}

export function generateX25519KeyPair(): X25519KeyPair {
  const secretKey = x25519.utils.randomPrivateKey();
  const publicKey = x25519.getPublicKey(secretKey);
  return { publicKey, secretKey };
}

function deriveSymmetricKey(sharedSecret: Uint8Array, ephemeralPublicKey: Uint8Array, recipientPublicKey: Uint8Array): Uint8Array {
  const salt = concatBytes(ephemeralPublicKey, recipientPublicKey);
  return hkdf(sha256, sharedSecret, salt, HKDF_INFO, 32);
}

export async function sealedBoxEncrypt(plaintext: Uint8Array, recipientPublicKey: Uint8Array): Promise<Uint8Array> {
  if (recipientPublicKey.length !== PUBLIC_KEY_LENGTH) throw new Error('Invalid X25519 public key length');
  const ephemeral = generateX25519KeyPair();
  const sharedSecret = x25519.getSharedSecret(ephemeral.secretKey, recipientPublicKey);
  const symmetricKey = deriveSymmetricKey(sharedSecret, ephemeral.publicKey, recipientPublicKey);
  const { iv, ciphertext } = await aesGcmEncrypt(plaintext, symmetricKey);

  const out = new Uint8Array(PUBLIC_KEY_LENGTH + IV_LENGTH + ciphertext.length);
  out.set(ephemeral.publicKey, 0);
  out.set(iv, PUBLIC_KEY_LENGTH);
  out.set(ciphertext, PUBLIC_KEY_LENGTH + IV_LENGTH);
  return out;
}

export async function sealedBoxDecrypt(sealed: Uint8Array, recipientSecretKey: Uint8Array): Promise<Uint8Array> {
  if (sealed.length < PUBLIC_KEY_LENGTH + IV_LENGTH + 16) throw new DecryptionError('Sealed box too short');
  const ephemeralPublicKey = sealed.slice(0, PUBLIC_KEY_LENGTH);
  const iv = sealed.slice(PUBLIC_KEY_LENGTH, PUBLIC_KEY_LENGTH + IV_LENGTH);
  const ciphertext = sealed.slice(PUBLIC_KEY_LENGTH + IV_LENGTH);

  const recipientPublicKey = x25519.getPublicKey(recipientSecretKey);
  const sharedSecret = x25519.getSharedSecret(recipientSecretKey, ephemeralPublicKey);
  const symmetricKey = deriveSymmetricKey(sharedSecret, ephemeralPublicKey, recipientPublicKey);
  return aesGcmDecrypt(ciphertext, symmetricKey, iv);
}
