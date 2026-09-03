export * from './types';
export { manualFileAdapter } from './manualFileAdapter';
export { concealedImageAdapter, setCarrierImage } from './concealedImageAdapter';
export { phantomRelayAdapter, setRelayPolicy, type RelayPolicy } from './phantomRelayAdapter';
export * from './receive';

import type { TransportAdapter } from './types';
import { manualFileAdapter } from './manualFileAdapter';
import { concealedImageAdapter } from './concealedImageAdapter';
import { phantomRelayAdapter } from './phantomRelayAdapter';

/** Ordered by how strongly each is recommended — bit-perfect paths first. */
export const ALL_ADAPTERS: TransportAdapter[] = [manualFileAdapter, phantomRelayAdapter, concealedImageAdapter];
