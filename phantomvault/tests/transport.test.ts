/**
 * concealedImageAdapter (and its compatibility self-test) is NOT covered
 * here: jsdom does not implement Canvas 2D / createImageBitmap, the same
 * limitation that keeps steganography.ts itself unit-test-free (see that
 * file's history). It's verified against a real browser engine instead —
 * see the session notes / manual verification for the live round-trip and
 * the compatibility self-test correctly reporting FAILED after simulated
 * JPEG recompression.
 */
import { describe, it, expect } from 'vitest';
import { manualFileAdapter } from '../src/lib/transport/manualFileAdapter';
import { receiveFromManualFile } from '../src/lib/transport/receive';

function randomBytes(len: number): Uint8Array {
  const b = new Uint8Array(len);
  crypto.getRandomValues(b);
  return b;
}

describe('manualFileAdapter', () => {
  it('is always available (no account/carrier needed)', () => {
    expect(manualFileAdapter.isAvailable()).toBe(true);
  });

  it('is labeled bit-perfect', () => {
    expect(manualFileAdapter.reliability).toBe('bit-perfect');
  });

  it('round-trips ciphertext bytes exactly through send() + receiveFromManualFile', async () => {
    const ciphertext = randomBytes(512);
    const result = await manualFileAdapter.send({ ciphertext, filename: 'x.phantom', mimeType: 'application/octet-stream' });
    expect(result.kind).toBe('download');
    expect(result.blob).toBeTruthy();

    const file = new File([result.blob!], result.downloadFilename ?? 'out.phantom');
    const recovered = await receiveFromManualFile(file);
    expect(Array.from(recovered)).toEqual(Array.from(ciphertext));
  });

  it('never adds anything to the payload beyond what was passed in — no metadata leak', async () => {
    const ciphertext = randomBytes(64);
    const result = await manualFileAdapter.send({ ciphertext, filename: 'secret-name.txt', mimeType: 'text/plain' });
    const bytes = new Uint8Array(await result.blob!.arrayBuffer());
    expect(bytes.length).toBe(ciphertext.length);
  });
});
