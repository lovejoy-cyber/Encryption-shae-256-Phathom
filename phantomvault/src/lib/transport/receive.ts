/**
 * Recovers raw ciphertext bytes from whichever channel the recipient
 * received them through. Deliberately does NOT decrypt or unpack — every
 * channel converges on the same one decrypt+unpack step in the calling
 * UI, so there's exactly one place that logic can be wrong, not three.
 */
import { receiveFromConcealedImage } from './concealedImageAdapter';
import { releaseCapability } from '../backendClient';

export async function receiveFromManualFile(file: File): Promise<Uint8Array> {
  return new Uint8Array(await file.arrayBuffer());
}

export { receiveFromConcealedImage };

export async function receiveFromRelay(capabilityId: string): Promise<Uint8Array> {
  return releaseCapability(capabilityId.trim());
}
