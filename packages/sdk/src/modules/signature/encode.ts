import {
  BytesLike,
  concat,
  hexlify,
  arrayify,
  BigNumberish,
  BigNumberCoder,
} from 'fuels';

const PREFIX_BAKO_SIG = '0x42414b4f';

export enum SignatureType {
  WebAuthn = 0,
  Fuel = 1,
}

export type WebAuthnInput = {
  type: SignatureType.WebAuthn;
  signature: BytesLike;
  prefix: BytesLike;
  suffix: BytesLike;
  authData: BytesLike;
};

export type FuelInput = {
  type: SignatureType.Fuel;
  signature: BytesLike;
};

type BakoCoder<T = unknown, D = unknown> = {
  type: T;
  encode(data: D): string;
  decode?(data: string): D;
};

export type SignatureTypes = WebAuthnInput | FuelInput;

function createCoder<T extends SignatureType>(
  type: T,
  encode: (data: Extract<SignatureTypes, { type: T }>) => string,
  decode?: (data: string) => Extract<SignatureTypes, { type: T }>,
): BakoCoder<T> {
  return {
    type,
    encode,
    decode,
  };
}

const BakoCoders: Array<BakoCoder> = [
  createCoder(SignatureType.WebAuthn, (data) => {
    const prefixBytes = arrayify(data.prefix);
    const suffixBytes = arrayify(data.suffix);
    const authDataBytes = arrayify(data.authData);
    return hexlify(
      concat([
        data.signature, // get Unit8Array of bn
        new BigNumberCoder('u64').encode(prefixBytes.length), // prefix size
        new BigNumberCoder('u64').encode(suffixBytes.length), // suffix size
        new BigNumberCoder('u64').encode(authDataBytes.length), // authdata size
        prefixBytes,
        suffixBytes,
        authDataBytes,
      ]),
    );
  }),
  createCoder(SignatureType.Fuel, (data) => {
    return hexlify(arrayify(data.signature));
  }),
];

export function encode(data: SignatureTypes): string {
  const signarure: Array<BytesLike> = [PREFIX_BAKO_SIG];
  if (SignatureType[data.type] !== undefined) {
    new Error('Invalid signature type');
  }
  signarure.push(new BigNumberCoder('u64').encode(data.type));

  const coder = BakoCoders.find((c) => c.type === data.type);
  if (!coder) {
    throw new Error('Encoder not found!');
  }
  signarure.push(coder.encode(data));
  return hexlify(concat(signarure));
}

// type Signature =
//   | {
//       type: SignatureType.WebAuthn;
//       signature: string;
//       prefix: string;
//       suffix: string;
//       authData: string;
//     }
//   | {
//       type: SignatureType.Fuel;
//       signature: string;
//     };

// function encodeSignature(sig: Signature) {
//   const typeBytes = new BigNumberCoder('u64').encode(sig.type);
//   switch (sig.type) {
//     case SignatureType.WEB_AUTHN: {
//     }
//     case SignatureType.FUEL:
//       return concat([typeBytes, sig.signature]);
//     default:
//       throw new Error('Not implemented');
//   }
// }
