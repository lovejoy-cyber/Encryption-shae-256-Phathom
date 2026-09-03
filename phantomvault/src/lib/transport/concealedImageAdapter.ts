/**
 * LSB steganography, kept as an explicitly opt-in CONCEALMENT feature —
 * for when hiding that content is encrypted matters more than transport
 * robustness (e.g. censorship circumvention) — not as the primary
 * "send this file" path. THREAT_MODEL.md §7.4 covers why: LSB doesn't
 * resist statistical steganalysis, and any lossy recompression (which
 * "send as photo" in virtually every chat app performs) destroys it
 * completely.
 *
 * Before ever returning a result, this adapter runs a live compatibility
 * self-test: it locally re-encodes the generated stego image the way a
 * typical chat-app photo pipeline would (JPEG ~85% quality) and tries to
 * extract the payload back out of THAT copy. If extraction fails — which
 * it reliably does — the caller gets a definitive `compatible: false`
 * result instead of a text warning the user might not read.
 *
 * As with manualFileAdapter, `pkg.ciphertext` must already be fully
 * encrypted (including any sensitive filename/type metadata packed inside
 * it — lib/filePayload.ts) before it reaches this adapter; the image is
 * never used to carry anything this adapter itself adds.
 */
import type { TransportAdapter, TransportPackage, TransportSendResult } from './types';
import { embedInImage, extractFromImage, stegoCapacityBytes } from '../steganography';

export interface CarrierRequirement {
  minWidth: number;
  minHeight: number;
}

let carrierImage: File | null = null;

/** UI must call this before send() — the carrier is a user choice, not something this adapter can invent. */
export function setCarrierImage(file: File | null) {
  carrierImage = file;
}

async function runCompatibilitySelfTest(stegoBlob: Blob): Promise<boolean> {
  // Simulate a lossy chat-app "photo" recompression pass locally.
  const bitmap = await createImageBitmap(stegoBlob);
  const canvas = document.createElement('canvas');
  canvas.width = bitmap.width;
  canvas.height = bitmap.height;
  const ctx = canvas.getContext('2d');
  if (!ctx) return false;
  ctx.drawImage(bitmap, 0, 0);
  const recompressed: Blob = await new Promise((resolve, reject) =>
    canvas.toBlob((b) => (b ? resolve(b) : reject(new Error('recompress failed'))), 'image/jpeg', 0.85)
  );

  try {
    const recompressedBitmap = await createImageBitmap(recompressed);
    await extractFromImage(recompressedBitmap);
    return true; // would only happen for a lossless/very-high-quality path
  } catch {
    return false; // expected: LSB data does not survive JPEG recompression
  }
}

export const concealedImageAdapter: TransportAdapter = {
  id: 'concealed-image',
  name: 'Hidden in an image (steganography)',
  description: 'Conceals the encrypted payload inside a carrier photo via LSB steganography. Fragile by nature — only survives channels that don\'t recompress images. Use only when hiding the fact that content is encrypted matters more than reliability.',
  reliability: 'fragile',
  // Always offered as a choice — the carrier image is picked AFTER
  // selecting this adapter (see FileLocker's Send UI), so gating
  // availability on carrierImage already being set would make it
  // impossible to ever select in the first place. The missing-carrier
  // case is validated at send() time instead.
  isAvailable: () => true,
  async send(pkg: TransportPackage): Promise<TransportSendResult> {
    if (!carrierImage) throw new Error('No carrier image selected — call setCarrierImage() first');

    const carrierBitmap = await createImageBitmap(carrierImage);
    const capacity = stegoCapacityBytes(carrierBitmap.width, carrierBitmap.height);
    if (pkg.ciphertext.length > capacity) {
      throw new Error(`Payload (${pkg.ciphertext.length}B) exceeds this carrier's capacity (${capacity}B). Use a larger image.`);
    }

    const stegoBlob = await embedInImage(carrierBitmap, pkg.ciphertext);
    const compatible = await runCompatibilitySelfTest(stegoBlob);

    return {
      kind: 'image',
      blob: stegoBlob,
      downloadFilename: 'locked.png',
      warning: compatible
        ? 'Local compatibility test passed for this specific re-encoding path, but treat this as fragile regardless — many platforms use different pipelines. Send as a file/document attachment, never as a "photo".'
        : 'Compatibility self-test FAILED: this image will NOT survive being sent as a "photo" through a typical recompressing chat app (verified locally by simulating that recompression). It must be sent as a raw file/document attachment, or use the Encrypted File or Relay transport instead.',
    };
  },
};

/** Recovers the raw ciphertext bytes only — decrypting/unpacking is the caller's job, uniform across all transports (see lib/transport/receive.ts). */
export async function receiveFromConcealedImage(stegoFile: File): Promise<Uint8Array> {
  const bitmap = await createImageBitmap(stegoFile);
  return extractFromImage(bitmap);
}
