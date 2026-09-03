import { describe, it, expect } from 'vitest';
import { sniffFileType, shannonEntropy, scanFile } from '../src/lib/fileScanner';

describe('file scanner', () => {
  it('sniffs a PNG signature', () => {
    const bytes = new Uint8Array([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a]);
    expect(sniffFileType(bytes)?.mime).toBe('image/png');
  });

  it('sniffs a Windows executable (MZ header)', () => {
    const bytes = new Uint8Array([0x4d, 0x5a, 0x90, 0x00]);
    expect(sniffFileType(bytes)?.mime).toBe('application/x-msdownload');
  });

  it('returns null for unrecognized content', () => {
    const bytes = new Uint8Array([0x01, 0x02, 0x03, 0x04]);
    expect(sniffFileType(bytes)).toBeNull();
  });

  it('entropy of a single repeated byte is ~0', () => {
    const bytes = new Uint8Array(1024).fill(0x41);
    expect(shannonEntropy(bytes)).toBeCloseTo(0, 5);
  });

  it('entropy of uniformly random-looking bytes approaches 8', () => {
    const bytes = new Uint8Array(4096);
    for (let i = 0; i < bytes.length; i++) bytes[i] = i % 256; // all 256 values equally represented
    expect(shannonEntropy(bytes)).toBeCloseTo(8, 1);
  });

  it('flags a file whose extension lies about its content', async () => {
    const peBytes = new Uint8Array([0x4d, 0x5a, 0x90, 0x00, 0x03, 0x00, 0x00, 0x00]);
    const disguised = new File([peBytes], 'totally-a-photo.png', { type: 'image/png' });
    const report = await scanFile(disguised);
    expect(report.typeMismatch).toBe(true);
    expect(report.executableWarning).toBe(true);
    expect(report.warnings.length).toBeGreaterThan(0);
  });

  it('does not flag a well-formed matching file', async () => {
    const pngBytes = new Uint8Array([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a, 1, 2, 3, 4]);
    const clean = new File([pngBytes], 'photo.png', { type: 'image/png' });
    const report = await scanFile(clean);
    expect(report.typeMismatch).toBe(false);
    expect(report.executableWarning).toBe(false);
  });
});
