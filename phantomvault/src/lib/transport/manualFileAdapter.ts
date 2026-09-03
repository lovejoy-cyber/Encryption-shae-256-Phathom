/**
 * The most robust "send this anywhere" path: the encrypted payload is
 * exported as an opaque `.phantom` binary file. Because it isn't disguised
 * as an image (or anything else a chat app "understands"), there's no
 * pixel/format for a recompression pipeline to mangle — WhatsApp, Telegram,
 * email, USB, AirDrop all treat an unrecognized file extension as a plain
 * attachment and pass it through byte-for-byte. This sidesteps the
 * steganography-survivability problem structurally rather than fighting it.
 *
 * `pkg.ciphertext` must already be fully encrypted, with any sensitive
 * metadata (real filename/type) packed inside it by the caller (see
 * lib/filePayload.ts) BEFORE it reaches this adapter — this adapter never
 * adds anything to the payload, so it can't leak anything the caller
 * didn't already encrypt. `pkg.filename`/`pkg.mimeType` here describe only
 * the outer wrapper file, not the real content.
 */
import type { TransportAdapter, TransportPackage, TransportSendResult } from './types';

export const manualFileAdapter: TransportAdapter = {
  id: 'manual-file',
  name: 'Encrypted file (.phantom)',
  description: 'Downloads an opaque encrypted file. Send it through any app as a document/file attachment — bit-perfect on any channel, since there\'s no image format for a chat app to recompress.',
  reliability: 'bit-perfect',
  isAvailable: () => true,
  async send(pkg: TransportPackage): Promise<TransportSendResult> {
    const blob = new Blob([pkg.ciphertext as BlobPart], { type: 'application/octet-stream' });
    return {
      kind: 'download',
      blob,
      downloadFilename: `${pkg.filename.replace(/\.[^.]+$/, '')}.phantom`,
      warning: 'Send this as a file/document attachment, not inline media — most chat apps preserve document attachments byte-for-byte.',
    };
  },
};
