/**
 * Transport abstraction (docs/ARCHITECTURE.md §6, THREAT_MODEL.md §7).
 *
 * Core principle: encryption and transport are separate concerns with
 * separate failure modes. Every adapter here receives bytes that are
 * ALREADY encrypted client-side — none of them ever see plaintext, and
 * none of them are responsible for confidentiality. Their only job is
 * getting ciphertext from sender to recipient intact, and being honest
 * about whether they can actually promise that.
 */

export interface TransportPackage {
  ciphertext: Uint8Array;
  filename: string;
  mimeType: string;
}

export type TransportReliability = 'bit-perfect' | 'fragile';

export interface TransportSendResult {
  /** How the result should be presented to the user. */
  kind: 'download' | 'share-code' | 'image';
  blob?: Blob;
  downloadFilename?: string;
  /** For share-code: what the sender tells the recipient out-of-band (e.g. paste into WhatsApp). */
  shareCode?: string;
  /** Non-fatal caveats to show alongside a successful result (e.g. the stego "send as file" warning). */
  warning?: string;
}

export interface TransportAdapter {
  id: string;
  name: string;
  description: string;
  reliability: TransportReliability;
  /** Whether this adapter is usable right now (e.g. PhantomRelay needs a backend connection). */
  isAvailable(): boolean;
  send(pkg: TransportPackage): Promise<TransportSendResult>;
}
