/**
 * File security scanner.
 *
 * Honest about what this is: client-side heuristics (magic-byte sniffing,
 * extension/content mismatch, Shannon entropy), NOT a malware engine.
 * There is no bundled antivirus and no hardcoded API key. The optional
 * lookupHashReputation() call is a pluggable integration point — it sends
 * only a SHA-256 hash (never file bytes) to VirusTotal, and only runs if
 * the caller supplies their own API key.
 */

import { sha256Hex } from "./crypto";

interface FileTypeSignature {
  mime: string;
  label: string;
  magic: number[];
  offset?: number;
}

const SIGNATURES: FileTypeSignature[] = [
  { mime: "image/png", label: "PNG image", magic: [0x89, 0x50, 0x4e, 0x47] },
  { mime: "image/jpeg", label: "JPEG image", magic: [0xff, 0xd8, 0xff] },
  { mime: "image/gif", label: "GIF image", magic: [0x47, 0x49, 0x46, 0x38] },
  { mime: "application/pdf", label: "PDF document", magic: [0x25, 0x50, 0x44, 0x46] },
  { mime: "application/zip", label: "ZIP archive (also docx/xlsx/apk/jar)", magic: [0x50, 0x4b, 0x03, 0x04] },
  { mime: "application/x-msdownload", label: "Windows executable (PE/EXE/DLL)", magic: [0x4d, 0x5a] },
  { mime: "application/x-elf", label: "Linux executable (ELF)", magic: [0x7f, 0x45, 0x4c, 0x46] },
  { mime: "application/x-rar-compressed", label: "RAR archive", magic: [0x52, 0x61, 0x72, 0x21] },
];

function bytesMatch(bytes: Uint8Array, sig: FileTypeSignature): boolean {
  const offset = sig.offset ?? 0;
  if (bytes.length < offset + sig.magic.length) return false;
  return sig.magic.every((b, i) => bytes[offset + i] === b);
}

export function sniffFileType(bytes: Uint8Array): { mime: string; label: string } | null {
  for (const sig of SIGNATURES) {
    if (bytesMatch(bytes, sig)) return { mime: sig.mime, label: sig.label };
  }
  return null;
}

export function shannonEntropy(bytes: Uint8Array): number {
  if (bytes.length === 0) return 0;
  const freq = new Array(256).fill(0);
  for (const b of bytes) freq[b]++;
  let entropy = 0;
  for (const count of freq) {
    if (count === 0) continue;
    const p = count / bytes.length;
    entropy -= p * Math.log2(p);
  }
  return entropy;
}

export interface ScanReport {
  name: string;
  size: number;
  sha256: string;
  claimedType: string;
  detectedType: string | null;
  typeMismatch: boolean;
  entropy: number;
  highEntropyWarning: boolean;
  executableWarning: boolean;
  warnings: string[];
}

const ENTROPY_SAMPLE_BYTES = 65536;

export async function scanFile(file: File): Promise<ScanReport> {
  const buf = new Uint8Array(await file.arrayBuffer());
  const sha256 = await sha256Hex(buf);
  const detected = sniffFileType(buf);
  const entropy = shannonEntropy(buf.slice(0, ENTROPY_SAMPLE_BYTES));
  const warnings: string[] = [];

  const typeMismatch = detected !== null && file.type !== "" && detected.mime !== file.type;
  if (typeMismatch) {
    warnings.push(
      `Extension/MIME claims "${file.type}" but the content signature is "${detected!.label}". Mismatched file types are a classic malware-disguise technique.`
    );
  }

  const executableWarning = detected?.mime === "application/x-msdownload" || detected?.mime === "application/x-elf";
  if (executableWarning) {
    warnings.push(`Content signature matches an executable (${detected!.label}). Do not run unless you fully trust the source.`);
  }

  const highEntropyWarning = entropy > 7.5;
  if (highEntropyWarning) {
    warnings.push("High byte-entropy — the file is likely already compressed, encrypted, or packed. Not inherently malicious, but worth a second look if unexpected.");
  }

  return {
    name: file.name,
    size: file.size,
    sha256,
    claimedType: file.type || "(none provided)",
    detectedType: detected?.mime ?? null,
    typeMismatch,
    entropy,
    highEntropyWarning,
    executableWarning,
    warnings,
  };
}

export interface HashReputation {
  malicious: number;
  suspicious: number;
  harmless: number;
}

/** Optional. Sends only the SHA-256 hash — never file content — to VirusTotal. Requires the user's own API key. */
export async function lookupHashReputation(sha256: string, virusTotalApiKey: string): Promise<HashReputation | null> {
  const res = await fetch(`https://www.virustotal.com/api/v3/files/${sha256}`, {
    headers: { "x-apikey": virusTotalApiKey },
  });
  if (res.status === 404) return null;
  if (!res.ok) throw new Error(`VirusTotal lookup failed: HTTP ${res.status}`);
  const json = await res.json();
  const stats = json?.data?.attributes?.last_analysis_stats;
  if (!stats) return null;
  return { malicious: stats.malicious ?? 0, suspicious: stats.suspicious ?? 0, harmless: stats.harmless ?? 0 };
}
