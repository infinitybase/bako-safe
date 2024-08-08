import { arrayify, hash, hexlify, randomBytes } from 'fuels';

import { findIndex, fromBase64, hexToASCII } from './bytes';
import { getSignature, parsePublicKey, sha256 } from './crypto';

export function splitCLientData(
  clientData: Uint8Array | ArrayBuffer,
  challangeBytesInASCII: Uint8Array,
) {
  const clientDataArray = new Uint8Array(clientData);
  const challangeIndex = findIndex(clientDataArray, challangeBytesInASCII);
  if (challangeIndex === -1) {
    throw new Error('Challange not found!');
  }
  return {
    prefix: hexlify(clientDataArray.slice(0, challangeIndex)),
    suffix: hexlify(
      clientDataArray.slice(challangeIndex + challangeBytesInASCII.length),
    ),
  };
}

export async function createAccount(username: string, challenge: string) {
  const id = randomBytes(32);
  const credential = await navigator.credentials.create({
    publicKey: {
      challenge: arrayify(challenge),
      rp: {
        id: window.location.hostname,
        name: window.location.hostname,
      },
      user: {
        id,
        name: username,
        displayName: username,
      },
      pubKeyCredParams: [
        {
          alg: -7,
          type: 'public-key',
        },
      ],
      authenticatorSelection: {
        userVerification: 'required',
        residentKey: 'preferred',
        requireResidentKey: false,
      },
      attestation: 'none',
      timeout: 60000,
    },
  });

  const response = (credential as any).response;

  const publicKey = await parsePublicKey(response.getPublicKey());
  const publicKeyHex = hexlify(new Uint8Array(publicKey.slice(1)));

  return {
    id,
    publicKey: publicKey.slice(1),
    address: hash(new Uint8Array(publicKey.slice(1))),
    authenticatorData: response.authenticatorData,
    clientData: response.clientDataJSON,
    credential,
    publicKeyHex,
  };
}

export async function formatToWebAuthnCreate({
  authenticatorData,
  clientDataJSON,
  signature,
  publicKey,
}: {
  authenticatorData: Uint8Array;
  clientDataJSON: Uint8Array;
  publicKey: string;
  signature: Uint8Array | ArrayBuffer;
}) {
  const authData = new Uint8Array(authenticatorData);
  const clientHash = await sha256(clientDataJSON);

  const digest = await sha256(new Uint8Array([...authData, ...clientHash]));
  const sig = getSignature(publicKey, signature, digest).sig_compact;

  return {
    sig,
    digest,
  };
}

export async function signChallange(
  id: string,
  challenge: string,
  publicKey: string,
) {
  const challangeBytesInASCII = hexToASCII(challenge);

  const authentication = await navigator.credentials.get({
    publicKey: {
      challenge: fromBase64(challenge.slice(2)),
      rpId: window.location.hostname,
      allowCredentials: [
        {
          id: fromBase64(id),
          type: 'public-key',
          transports: ['hybrid', 'internal'],
        },
      ],
      userVerification: 'required',
      timeout: 60000,
    },
  });
  const response = (authentication as any).response;
  const authData = new Uint8Array(response.authenticatorData);
  const clientHash = await sha256(response.clientDataJSON);
  const digest = await sha256(new Uint8Array([...authData, ...clientHash]));

  return {
    ...getSignature(publicKey, response.signature, digest),
    ...splitCLientData(response.clientDataJSON, challangeBytesInASCII),
    authData: hexlify(authData),
  };
}
