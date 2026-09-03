import { describe, it, expect } from 'vitest';
import { createEphemeralMessage, openEphemeralMessage, AlreadyOpenedError, ExpiredMessageError } from '../src/lib/ephemeral';

describe('ephemeral messaging', () => {
  it('opens a message with no timer normally', async () => {
    const payload = await createEphemeralMessage('hi', 'pw', { expiresAt: null, burnAfterReading: false });
    const body = await openEphemeralMessage(payload, 'pw');
    expect(body).toBe('hi');
  });

  it('refuses to open an already-expired message', async () => {
    const payload = await createEphemeralMessage('hi', 'pw', { expiresAt: Date.now() - 1000, burnAfterReading: false });
    await expect(openEphemeralMessage(payload, 'pw')).rejects.toThrow(ExpiredMessageError);
  });

  it('allows a non-expired timed message through', async () => {
    const payload = await createEphemeralMessage('hi', 'pw', { expiresAt: Date.now() + 60_000, burnAfterReading: false });
    const body = await openEphemeralMessage(payload, 'pw');
    expect(body).toBe('hi');
  });

  it('burn-after-reading: first open succeeds, second open on same payload fails', async () => {
    const payload = await createEphemeralMessage('one-time secret', 'pw', { expiresAt: null, burnAfterReading: true });
    const first = await openEphemeralMessage(payload, 'pw');
    expect(first).toBe('one-time secret');
    await expect(openEphemeralMessage(payload, 'pw')).rejects.toThrow(AlreadyOpenedError);
  });

  it('non burn-after-reading messages can be opened multiple times', async () => {
    const payload = await createEphemeralMessage('reusable', 'pw', { expiresAt: null, burnAfterReading: false });
    await expect(openEphemeralMessage(payload, 'pw')).resolves.toBe('reusable');
    await expect(openEphemeralMessage(payload, 'pw')).resolves.toBe('reusable');
  });
});
