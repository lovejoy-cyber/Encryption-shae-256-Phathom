import 'fake-indexeddb/auto';
import { webcrypto } from 'node:crypto';

if (!globalThis.crypto?.subtle) {
  // @ts-expect-error jsdom's crypto is incomplete; wire in Node's webcrypto for AES-GCM/PBKDF2 tests
  globalThis.crypto = webcrypto;
}
