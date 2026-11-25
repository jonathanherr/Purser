import { describe, expect, it } from 'vitest';
import { seal, unseal } from '../src/crypto/envelope.js';
import { testKey } from './helpers.js';

describe('envelope encryption', () => {
  it('round-trips a secret', async () => {
    const kp = testKey();
    const s = await seal(kp, 'access-sandbox-123', 'ctx:item-1');
    expect(s.ciphertext).not.toContain('access-sandbox');
    expect(await unseal(kp, s, 'ctx:item-1')).toBe('access-sandbox-123');
  });

  it('refuses a ciphertext moved to another row', async () => {
    const kp = testKey();
    const s = await seal(kp, 'secret', 'ctx:item-1');
    await expect(unseal(kp, s, 'ctx:item-2')).rejects.toThrow();
  });

  it('refuses a different master key', async () => {
    const s = await seal(testKey(), 'secret', 'ctx');
    await expect(unseal(testKey(), s, 'ctx')).rejects.toThrow();
  });

  it('detects tampering', async () => {
    const kp = testKey();
    const s = await seal(kp, 'secret', 'ctx');
    const [iv, tag, ct] = s.ciphertext.split('.');
    const flipped = Buffer.from(ct!, 'base64');
    flipped[0] = flipped[0]! ^ 1;
    await expect(unseal(kp, { ...s, ciphertext: [iv, tag, flipped.toString('base64')].join('.') }, 'ctx')).rejects.toThrow();
  });
});
