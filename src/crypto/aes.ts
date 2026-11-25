import { createCipheriv, createDecipheriv, randomBytes } from 'node:crypto';

/** AES-256-GCM with a random 96-bit IV. Output: base64 iv.tag.ciphertext. The aad binds context. */
export function aesGcmEncrypt(key: Buffer, plaintext: Buffer, aad: string): string {
  const iv = randomBytes(12);
  const cipher = createCipheriv('aes-256-gcm', key, iv);
  cipher.setAAD(Buffer.from(aad));
  const ct = Buffer.concat([cipher.update(plaintext), cipher.final()]);
  return [iv, cipher.getAuthTag(), ct].map((b) => b.toString('base64')).join('.');
}

export function aesGcmDecrypt(key: Buffer, sealed: string, aad: string): Buffer {
  const [iv, tag, ct] = sealed.split('.').map((s) => Buffer.from(s, 'base64'));
  if (!iv || !tag || !ct) throw new Error('malformed ciphertext');
  const decipher = createDecipheriv('aes-256-gcm', key, iv);
  decipher.setAAD(Buffer.from(aad));
  decipher.setAuthTag(tag);
  return Buffer.concat([decipher.update(ct), decipher.final()]);
}
