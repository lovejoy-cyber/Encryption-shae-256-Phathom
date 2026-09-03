/**
 * LSB (least-significant-bit) image steganography.
 *
 * We flip the bottom bit of the R, G and B channel of each pixel (alpha is
 * left untouched) to encode a 32-bit big-endian length header followed by
 * the payload bytes. One bit per channel is visually imperceptible and is
 * the standard, well-studied approach.
 *
 * IMPORTANT REAL-WORLD CAVEAT (surfaced in the UI too): messaging apps
 * that recompress "photos" — WhatsApp, Telegram's default photo mode,
 * Messenger — will re-encode the image and destroy every hidden bit.
 * The carrier image MUST be sent as a raw file/document attachment, not
 * shared through a "photo" picker.
 */

const HEADER_BITS = 32;

export function stegoCapacityBytes(width: number, height: number): number {
  const usableBits = width * height * 3; // R, G, B — 1 bit each, alpha untouched
  return Math.max(0, Math.floor((usableBits - HEADER_BITS) / 8));
}

function setLSB(byte: number, bit: number): number {
  return (byte & 0xfe) | (bit & 1);
}

function getLSB(byte: number): number {
  return byte & 1;
}

function bitAt(bytes: Uint8Array, bitIndex: number): number {
  const byteIdx = bitIndex >> 3;
  const bitInByte = 7 - (bitIndex % 8);
  return (bytes[byteIdx] >> bitInByte) & 1;
}

export async function embedInImage(carrier: ImageBitmap, payload: Uint8Array): Promise<Blob> {
  const capacity = stegoCapacityBytes(carrier.width, carrier.height);
  if (payload.length > capacity) {
    throw new Error(
      `Payload too large: ${payload.length} bytes, this carrier image can hold ${capacity} bytes. Use a larger/higher-resolution image.`
    );
  }

  const canvas = document.createElement("canvas");
  canvas.width = carrier.width;
  canvas.height = carrier.height;
  const ctx = canvas.getContext("2d");
  if (!ctx) throw new Error("Canvas 2D context unavailable");
  ctx.drawImage(carrier, 0, 0);
  const imageData = ctx.getImageData(0, 0, canvas.width, canvas.height);
  const data = imageData.data;

  const framed = new Uint8Array(4 + payload.length);
  new DataView(framed.buffer).setUint32(0, payload.length, false);
  framed.set(payload, 4);

  const totalBits = framed.length * 8;
  let bitIndex = 0;
  for (let pixelStart = 0; pixelStart < data.length && bitIndex < totalBits; pixelStart += 4) {
    for (let channel = 0; channel < 3 && bitIndex < totalBits; channel++) {
      data[pixelStart + channel] = setLSB(data[pixelStart + channel], bitAt(framed, bitIndex));
      bitIndex++;
    }
  }

  ctx.putImageData(imageData, 0, 0);
  return new Promise((resolve, reject) => {
    canvas.toBlob((blob) => (blob ? resolve(blob) : reject(new Error("PNG encoding failed"))), "image/png");
  });
}

export async function extractFromImage(stego: ImageBitmap): Promise<Uint8Array> {
  const canvas = document.createElement("canvas");
  canvas.width = stego.width;
  canvas.height = stego.height;
  const ctx = canvas.getContext("2d");
  if (!ctx) throw new Error("Canvas 2D context unavailable");
  ctx.drawImage(stego, 0, 0);
  const imageData = ctx.getImageData(0, 0, canvas.width, canvas.height);
  const data = imageData.data;

  function readBits(numBits: number, startBit: number): Uint8Array {
    const out = new Uint8Array(Math.ceil(numBits / 8));
    for (let i = 0; i < numBits; i++) {
      const globalBit = startBit + i;
      const pixelGroup = Math.floor(globalBit / 3);
      const channel = globalBit % 3;
      const dataIdx = pixelGroup * 4 + channel;
      const bit = dataIdx < data.length ? getLSB(data[dataIdx]) : 0;
      const byteIdx = i >> 3;
      const bitInByte = 7 - (i % 8);
      out[byteIdx] |= bit << bitInByte;
    }
    return out;
  }

  const lengthBytes = readBits(HEADER_BITS, 0);
  const payloadLength = new DataView(lengthBytes.buffer).getUint32(0, false);
  const maxCapacity = stegoCapacityBytes(stego.width, stego.height);

  if (payloadLength === 0 || payloadLength > maxCapacity) {
    throw new Error(
      "No valid PhantomVault payload found in this image. It may not contain hidden data, or it was re-compressed by a messaging app (always send/receive as a file attachment, never as a 'photo')."
    );
  }

  return readBits(payloadLength * 8, HEADER_BITS);
}

export async function fileToImageBitmap(file: File | Blob): Promise<ImageBitmap> {
  return createImageBitmap(file);
}
