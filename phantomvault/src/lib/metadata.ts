/**
 * Metadata / forensic cleaner.
 *
 * Decoding an image into a <canvas> and re-encoding it drops every
 * ancillary chunk the original file carried — EXIF GPS coordinates,
 * camera/device model, timestamps, author/software tags, embedded
 * thumbnails — because canvas only ever holds raw pixels. We ask the
 * decoder to respect EXIF orientation while decoding so the picture still
 * looks right after the orientation tag itself is stripped.
 */

export interface StripResult {
  blob: Blob;
  originalBytes: number;
  cleanedBytes: number;
}

export async function stripImageMetadata(
  file: File,
  outputType: "image/png" | "image/jpeg" = "image/jpeg",
  quality = 0.95
): Promise<StripResult> {
  const bitmap = await createImageBitmap(file, { imageOrientation: "from-image" });
  const canvas = document.createElement("canvas");
  canvas.width = bitmap.width;
  canvas.height = bitmap.height;
  const ctx = canvas.getContext("2d");
  if (!ctx) throw new Error("Canvas 2D context unavailable");
  ctx.drawImage(bitmap, 0, 0);

  const blob: Blob = await new Promise((resolve, reject) => {
    canvas.toBlob(
      (b) => (b ? resolve(b) : reject(new Error("Re-encoding failed"))),
      outputType,
      outputType === "image/jpeg" ? quality : undefined
    );
  });

  return { blob, originalBytes: file.size, cleanedBytes: blob.size };
}

/** Best-effort human-readable list of what a raw file *might* be carrying, for the "before" UI panel. */
export function detectLikelyMetadataFields(file: File): string[] {
  const found: string[] = [];
  if (file.type === "image/jpeg" || file.type === "image/tiff") {
    found.push("EXIF (camera model, GPS, timestamp)", "possible embedded thumbnail");
  }
  if (file.type === "image/png") {
    found.push("tEXt/iTXt ancillary chunks (software, author)");
  }
  if (file.type === "application/pdf") {
    found.push("PDF /Info dictionary (author, producer, creation date) — use a document, not image, cleaner for this");
  }
  return found;
}
