import { randomBytes } from 'node:crypto';
import { aesGcmDecrypt, aesGcmEncrypt } from './aes.js';
import { FieldCipher } from './fields.js';

/**
 * Envelope encryption for secrets at rest (Plaid access tokens).
 *
 * Each secret gets its own random 256-bit data key (DEK). The secret is encrypted with the DEK
 * using AES-256-GCM, and the DEK is wrapped by a KeyProvider. In production the provider is a
 * cloud KMS, so a database dump alone cannot decrypt anything.
 */
export interface KeyProvider {
  readonly keyId: string;
  /** Encrypts ledger fields (amounts, merchants, balances) at rest. See ./fields.ts. */
  readonly fields: FieldCipher;
  wrap(dek: Buffer): Promise<string>;
  unwrap(wrapped: string, keyId: string): Promise<Buffer>;
}

export interface SealedSecret {
  ciphertext: string;
  wrappedDek: string;
  keyId: string;
}

/**
 * Wraps data keys with a local master key from the environment. For development and tests only;
 * deploy with a KMS-backed provider (see KmsKeyProvider below).
 */
export class LocalKeyProvider implements KeyProvider {
  readonly keyId: string;
  readonly fields: FieldCipher;
  private readonly master: Buffer;

  constructor(masterKeyBase64: string, keyId = 'local-v1') {
    const key = Buffer.from(masterKeyBase64, 'base64');
    if (key.length !== 32) throw new Error('VAULT_MASTER_KEY must be 32 bytes, base64-encoded');
    this.master = key;
    this.keyId = keyId;
    this.fields = FieldCipher.fromMaster(key);
  }

  async wrap(dek: Buffer): Promise<string> {
    return aesGcmEncrypt(this.master, dek, `dek:${this.keyId}`);
  }

  async unwrap(wrapped: string, keyId: string): Promise<Buffer> {
    if (keyId !== this.keyId) throw new Error(`unknown key id ${keyId}`);
    return aesGcmDecrypt(this.master, wrapped, `dek:${this.keyId}`);
  }
}

/**
 * The context string binds a ciphertext to its row (for example the Plaid item id), so a
 * ciphertext copied onto another row fails to decrypt.
 */
export async function seal(kp: KeyProvider, plaintext: string, context: string): Promise<SealedSecret> {
  const dek = randomBytes(32);
  try {
    return {
      ciphertext: aesGcmEncrypt(dek, Buffer.from(plaintext, 'utf8'), context),
      wrappedDek: await kp.wrap(dek),
      keyId: kp.keyId,
    };
  } finally {
    dek.fill(0);
  }
}

export async function unseal(kp: KeyProvider, secret: SealedSecret, context: string): Promise<string> {
  const dek = await kp.unwrap(secret.wrappedDek, secret.keyId);
  try {
    return aesGcmDecrypt(dek, secret.ciphertext, context).toString('utf8');
  } finally {
    dek.fill(0);
  }
}
