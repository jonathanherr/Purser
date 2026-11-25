import { decodeProtectedHeader, importJWK, jwtVerify, type JWK } from 'jose';
import type { PlaidLike } from './client.js';
import { safeEqualHex, sha256Hex } from '../crypto/tokens.js';

const KEY_CACHE = new Map<string, JWK>();

/**
 * Verifies the Plaid-Verification header on an incoming webhook: an ES256 JWT signed by Plaid,
 * issued in the last 5 minutes, whose request_body_sha256 claim matches the raw body.
 * See https://plaid.com/docs/api/webhooks/webhook-verification/
 */
export async function verifyPlaidWebhook(
  plaid: PlaidLike,
  rawBody: string,
  jwt: string | undefined | null,
  keyCache = KEY_CACHE,
): Promise<boolean> {
  if (!jwt) return false;
  try {
    const header = decodeProtectedHeader(jwt);
    if (header.alg !== 'ES256' || !header.kid) return false;
    let jwk = keyCache.get(header.kid);
    if (!jwk) {
      jwk = await plaid.getWebhookVerificationKey(header.kid);
      keyCache.set(header.kid, jwk);
    }
    const key = await importJWK(jwk, 'ES256');
    const { payload } = await jwtVerify(jwt, key, { algorithms: ['ES256'], maxTokenAge: '5m' });
    const claimed = payload.request_body_sha256;
    return typeof claimed === 'string' && safeEqualHex(claimed, sha256Hex(rawBody));
  } catch {
    return false;
  }
}
