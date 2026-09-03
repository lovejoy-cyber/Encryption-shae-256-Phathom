/**
 * The server-mediated path: uploads the (already-encrypted) payload to the
 * backend's capability service, which wraps it in a second, server-held
 * encryption layer and returns a share code. This is the ONLY transport
 * that gains real server-enforced expiry/revocation — see
 * docs/ARCHITECTURE.md §5.2/§5.3. Requires being connected (a PhantomVault
 * backend account) — see features/Connect.
 */
import type { TransportAdapter, TransportPackage, TransportSendResult } from './types';
import { isConnected, createCapability } from '../backendClient';

export interface RelayPolicy {
  expiresAt?: Date | null;
  maxOpens?: number | null;
  orgId?: string;
}

let policy: RelayPolicy = {};
export function setRelayPolicy(p: RelayPolicy) {
  policy = p;
}

export const phantomRelayAdapter: TransportAdapter = {
  id: 'phantom-relay',
  name: 'PhantomVault Relay (recommended)',
  description: 'Uploads the encrypted payload to your PhantomVault account. Bit-perfect delivery over any network, plus real server-enforced expiry/revocation. Requires connecting an account.',
  reliability: 'bit-perfect',
  isAvailable: () => isConnected(),
  async send(pkg: TransportPackage): Promise<TransportSendResult> {
    if (!isConnected()) throw new Error('Connect a PhantomVault account first (see the Connect tab).');
    const capability = await createCapability({
      ciphertextInner: pkg.ciphertext,
      orgId: policy.orgId,
      expiresAt: policy.expiresAt,
      maxOpens: policy.maxOpens,
    });
    return {
      kind: 'share-code',
      shareCode: capability.id,
      warning: 'Share this code (and the password, separately) with the recipient. They need a PhantomVault account to open it.',
    };
  },
};
