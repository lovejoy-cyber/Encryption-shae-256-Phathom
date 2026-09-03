import { hkdf } from '@noble/hashes/hkdf';
import { sha256 as nobleSha256 } from '@noble/hashes/sha256';

/** General-purpose HKDF-SHA256 (RFC 5869), for deriving sub-keys from an existing high-entropy secret. */
export function hkdfSha256(ikm: Uint8Array, salt: Uint8Array, info: Uint8Array, length = 32): Uint8Array {
  return hkdf(nobleSha256, ikm, salt, info, length);
}
