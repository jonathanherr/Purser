import { createHash, createSign, generateKeyPairSync, randomBytes } from 'node:crypto';
import { isoCBOR } from '@simplewebauthn/server/helpers';

const BASE = 'https://vault.test';
const RP = 'vault.test';

export const b64u = (b: Uint8Array | Buffer) => Buffer.from(b).toString('base64url');
export const sha = (b: Uint8Array | Buffer | string) => createHash('sha256').update(b).digest();
const u32 = (n: number) => Buffer.from([(n >>> 24) & 255, (n >>> 16) & 255, (n >>> 8) & 255, n & 255]);

/** A software passkey: enough of an authenticator to register and sign like a phone would. */
export function softAuthenticator() {
  const { privateKey, publicKey } = generateKeyPairSync('ec', { namedCurve: 'P-256' });
  const jwk = publicKey.export({ format: 'jwk' });
  const credId = randomBytes(16);
  let counter = 0;
  const cose = isoCBOR.encode(
    new Map<number, number | Uint8Array>([
      [1, 2],
      [3, -7],
      [-1, 1],
      [-2, new Uint8Array(Buffer.from(jwk.x!, 'base64url'))],
      [-3, new Uint8Array(Buffer.from(jwk.y!, 'base64url'))],
    ]),
  );
  const clientData = (type: string, challenge: string, origin = BASE) =>
    Buffer.from(JSON.stringify({ type, challenge, origin, crossOrigin: false }));
  return {
    id: b64u(credId),
    register(challenge: string, origin = BASE) {
      const authData = Buffer.concat([sha(RP), Buffer.from([0x45]), u32(counter), Buffer.alloc(16), Buffer.from([0, credId.length]), credId, Buffer.from(cose)]);
      const att = isoCBOR.encode(new Map<string, unknown>([['fmt', 'none'], ['attStmt', new Map()], ['authData', new Uint8Array(authData)]]) as never);
      return {
        id: b64u(credId),
        rawId: b64u(credId),
        type: 'public-key',
        clientExtensionResults: {},
        response: { clientDataJSON: b64u(clientData('webauthn.create', challenge, origin)), attestationObject: b64u(att), transports: ['internal'] },
      };
    },
    sign(challenge: string, opts: { uv?: boolean; origin?: string } = {}) {
      counter += 1;
      const authData = Buffer.concat([sha(RP), Buffer.from([opts.uv === false ? 0x01 : 0x05]), u32(counter)]);
      const cd = clientData('webauthn.get', challenge, opts.origin);
      const signature = createSign('SHA256').update(Buffer.concat([authData, sha(cd)])).sign(privateKey);
      return {
        id: b64u(credId),
        rawId: b64u(credId),
        type: 'public-key',
        clientExtensionResults: {},
        response: { clientDataJSON: b64u(cd), authenticatorData: b64u(authData), signature: b64u(signature), userHandle: b64u(Buffer.from('jonathan')) },
      };
    },
  };
}

