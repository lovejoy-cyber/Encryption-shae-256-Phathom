/**
 * Packs a file's name + MIME type alongside its bytes into one binary blob,
 * so a single encrypted/steganographic payload is self-contained (no
 * side-channel needed to recover the original filename after extraction).
 * Layout: [u16 nameLen][name utf8][u16 typeLen][type utf8][raw bytes]
 */

export function packFile(name: string, type: string, bytes: Uint8Array): Uint8Array {
  const nameBytes = new TextEncoder().encode(name);
  const typeBytes = new TextEncoder().encode(type);
  const out = new Uint8Array(2 + nameBytes.length + 2 + typeBytes.length + bytes.length);
  const view = new DataView(out.buffer);
  let offset = 0;
  view.setUint16(offset, nameBytes.length, false);
  offset += 2;
  out.set(nameBytes, offset);
  offset += nameBytes.length;
  view.setUint16(offset, typeBytes.length, false);
  offset += 2;
  out.set(typeBytes, offset);
  offset += typeBytes.length;
  out.set(bytes, offset);
  return out;
}

export interface UnpackedFile {
  name: string;
  type: string;
  bytes: Uint8Array;
}

export function unpackFile(packed: Uint8Array): UnpackedFile {
  const view = new DataView(packed.buffer, packed.byteOffset, packed.byteLength);
  let offset = 0;
  const nameLen = view.getUint16(offset, false);
  offset += 2;
  const name = new TextDecoder().decode(packed.slice(offset, offset + nameLen));
  offset += nameLen;
  const typeLen = view.getUint16(offset, false);
  offset += 2;
  const type = new TextDecoder().decode(packed.slice(offset, offset + typeLen));
  offset += typeLen;
  const bytes = packed.slice(offset);
  return { name, type, bytes };
}
