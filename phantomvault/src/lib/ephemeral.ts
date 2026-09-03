/**
 * Ephemeral messaging on top of the core crypto engine.
 *
 * Honesty note (also surfaced in the UI): because the ciphertext the user
 * pastes into WhatsApp lives entirely outside our control once sent, a
 * pure client-side app cannot *cryptographically* guarantee a message is
 * unreadable after its timer expires — anyone holding both the ciphertext
 * and the shared password could still run the same math. What we CAN do
 * on-device, and do here, is:
 *   1. Embed the expiry + burn-after-reading policy inside the encrypted
 *      envelope itself (so it can't be stripped without the password), and
 *      refuse to render plaintext once that policy says no.
 *   2. Maintain a local "already opened" ledger so a burn-after-reading
 *      message can't be re-opened twice on the same device.
 * True server-enforced delete-on-read (so a captured copy of the
 * ciphertext is worthless after expiry even to someone with the password)
 * needs a server-side key escrow — see the Durable Object relay described
 * in README.md's roadmap for the enterprise tier.
 */

import { encryptText, decryptText, DecryptionError, sha256Hex } from "./crypto";
import { get, set, del, keys } from "idb-keyval";

export interface EphemeralPolicy {
  expiresAt: number | null; // epoch ms, null = no timer
  burnAfterReading: boolean;
}

interface EphemeralEnvelope {
  body: string;
  policy: EphemeralPolicy;
}

const LEDGER_PREFIX = "pv-opened:";
const LEDGER_TTL_MS = 30 * 24 * 60 * 60 * 1000; // garbage-collect ledger entries after 30 days

export class ExpiredMessageError extends Error {
  constructor() {
    super("This message's self-destruct timer has already expired.");
    this.name = "ExpiredMessageError";
  }
}

export class AlreadyOpenedError extends Error {
  constructor() {
    super("This burn-after-reading message was already opened on this device.");
    this.name = "AlreadyOpenedError";
  }
}

export async function createEphemeralMessage(
  message: string,
  password: string,
  policy: EphemeralPolicy
): Promise<string> {
  const envelope: EphemeralEnvelope = { body: message, policy };
  return encryptText(JSON.stringify(envelope), password);
}

/**
 * Decrypts and enforces policy. Throws ExpiredMessageError / AlreadyOpenedError
 * instead of returning plaintext when the policy forbids reading.
 * On a successful burn-after-reading open, records the ledger entry so a
 * second attempt on this device fails even with the correct password.
 */
export async function openEphemeralMessage(payload: string, password: string): Promise<string> {
  const ledgerKey = LEDGER_PREFIX + (await sha256Hex(new TextEncoder().encode(payload.trim())));

  const alreadyOpened = await get(ledgerKey);
  if (alreadyOpened) {
    throw new AlreadyOpenedError();
  }

  const json = await decryptText(payload, password);
  let envelope: EphemeralEnvelope;
  try {
    envelope = JSON.parse(json);
  } catch {
    throw new DecryptionError("Payload decrypted but was not a valid PhantomVault message");
  }

  if (envelope.policy.expiresAt !== null && Date.now() > envelope.policy.expiresAt) {
    throw new ExpiredMessageError();
  }

  if (envelope.policy.burnAfterReading) {
    await set(ledgerKey, Date.now());
  }

  return envelope.body;
}

/** Call periodically (e.g. on app start) to keep the ledger from growing forever. */
export async function pruneLedger(): Promise<void> {
  const now = Date.now();
  for (const k of await keys()) {
    if (typeof k === "string" && k.startsWith(LEDGER_PREFIX)) {
      const openedAt = await get(k);
      if (typeof openedAt === "number" && now - openedAt > LEDGER_TTL_MS) {
        await del(k);
      }
    }
  }
}

export const TIMER_PRESETS_MINUTES = [1, 5, 12, 30, 60] as const;
