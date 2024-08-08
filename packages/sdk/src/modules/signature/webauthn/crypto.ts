import { secp256r1 } from '@noble/curves/p256';
import { hexlify } from 'fuels';

import { EIP2090_encode } from './EIP2090';

export async function sha256(
  buffer: ArrayBuffer | Uint8Array,
): Promise<Uint8Array> {
  return new Uint8Array(await crypto.subtle.digest('SHA-256', buffer));
}

export async function parsePublicKey(publicKey: Uint8Array) {
  const cryptoKey = await crypto.subtle.importKey(
    'spki',
    publicKey,
    {
      name: 'ECDSA',
      namedCurve: 'P-256',
      hash: 'SHA-256',
    },
    true,
    ['verify'],
  );
  return await crypto.subtle.exportKey('raw', cryptoKey);
}

export function recoverPublicKey(
  signatureCompact: Uint8Array,
  digest: Uint8Array,
  recoveryBit: number,
) {
  const publicKey = secp256r1.Signature.fromCompact(signatureCompact)
    .addRecoveryBit(recoveryBit)
    .recoverPublicKey(digest);
  return `0x${publicKey.x.toString(16).padStart(64, '0')}${publicKey.y
    .toString(16)
    .padStart(64, '0')}`;
}

export function getRecoveryBit(
  publicKey: string,
  signatureCompact: Uint8Array,
  digest: Uint8Array,
) {
  return Number(recoverPublicKey(signatureCompact, digest, 0) !== publicKey);
}

export function convertASN1toRaw(signatureBuffer: ArrayBuffer | Uint8Array) {
  const usignature = new Uint8Array(signatureBuffer);

  const rStart = usignature[4] === 0 ? 5 : 4;
  const rEnd = rStart + 32;
  const sStart = usignature[rEnd + 2] === 0 ? rEnd + 3 : rEnd + 2;
  const r = usignature.slice(rStart, rEnd);
  const s = usignature.slice(sStart);
  const sig = new Uint8Array(64);
  const rs = [...r, ...s];
  sig.set(rs, 64 - rs.length);
  return sig;
}

export function getSignature(
  publicKey: string,
  signature: Uint8Array | ArrayBuffer,
  digest: Uint8Array,
): {
  signature: string;
  digest: string;
  sig_compact: Uint8Array;
  dig_compact: Uint8Array;
} {
  const signatureCompact = secp256r1.Signature.fromCompact(
    convertASN1toRaw(signature),
  )
    .normalizeS()
    .toCompactRawBytes();
  const recoveryBit = getRecoveryBit(publicKey, signatureCompact, digest);
  const sigatureCompactCopy = new Uint8Array(signatureCompact.slice());

  return {
    signature: hexlify(EIP2090_encode(sigatureCompactCopy, recoveryBit)),
    digest: hexlify(digest),
    sig_compact: signatureCompact,
    dig_compact: digest,
  };
}
