import {
  Provider,
  TransactionStatus,
  getRandomB256,
  bn,
  Wallet,
  concat,
  hexlify,
  Signer,
  hashMessage,
  bufferFromString,
  sha256,
  arrayify,
} from 'fuels';
import { secp256r1 } from '@noble/curves/p256';
import {
  signin,
  newVault,
  IUserAuth,
  authService,
  sendPredicateCoins,
} from './utils';
import { IPayloadVault, Vault, SignatureType, getSignature } from 'bakosafe';
import { BakoSafe } from 'bakosafe';
import {
  DEFAULT_BALANCES,
  accounts,
  DEFAULT_TRANSACTION_PAYLOAD,
  assets,
} from './mocks';

import {
  IPredicateVersion,
  makeSigners,
  makeHashPredicate,
  encode,
} from 'bakosafe';
import { PredicateAbi__factory } from '../../sdk/src/sway/predicates/factories/PredicateAbi__factory';
import { ScriptAbi__factory } from './types/sway/scripts';

function bigintToUint8Array(bigint: BigInt) {
  // Determine the number of bytes needed to represent the BigInt
  const byteLength = Math.ceil(bigint.toString(2).length / 8);

  // Create a Uint8Array of the appropriate length
  const uint8Array = new Uint8Array(byteLength);

  // Convert the BigInt to a hex string
  let hex = bigint.toString(16);

  // Ensure the hex string length is even
  if (hex.length % 2 !== 0) {
    hex = '0' + hex;
  }

  // Populate the Uint8Array with the bytes of the BigInt
  for (let i = 0; i < byteLength; i++) {
    uint8Array[byteLength - i - 1] = parseInt(hex.substr(i * 2, 2), 16);
  }

  return uint8Array;
}

// export const createPredicate = async ({
//   amount = '0.1',
//   minSigners = 3,
//   signers = [
//     accounts['USER_1'].account,
//     accounts['USER_3'].account,
//     accounts['USER_4'].account,
//   ],
// }: {
//   amount: string;
//   minSigners: number;
//   signers: string[];
// }) => {
//   const provider = await Provider.create(CHAIN_URL);
//   const _signers: [
//     string,
//     string,
//     string,
//     string,
//     string,
//     string,
//     string,
//     string,
//     string,
//     string,
//   ] = [
//     ZeroBytes32,
//     ZeroBytes32,
//     ZeroBytes32,
//     ZeroBytes32,
//     ZeroBytes32,
//     ZeroBytes32,
//     ZeroBytes32,
//     ZeroBytes32,
//     ZeroBytes32,
//     ZeroBytes32,
//   ];

//   for (let i = 0; i < 10; i++) {
//     _signers[i] = signers[i] ?? ZeroBytes32;
//   }

//   const input: PredicateAbiInputs = [];

//   //@ts-ignore
//   const predicate = PredicateAbi__factory.createInstance(provider, input, {
//     SIGNATURES_COUNT: minSigners ?? signers.length,
//     SIGNERS: _signers,
//     HASH_PREDICATE: Address.fromRandom().toB256(),
//   });

//   await seedAccount(predicate.address, bn.parseUnits(amount), provider);

//   return predicate;
// };

// configurable,
//     provider,
//     abi,
//     bytecode,
//     name,
//     description,
//     BakoSafeVaultId,
//     BakoSafeVault,
//     BakoSafeAuth,
//     transactionRecursiveTimeout = 1000,
//     api,
//     version,

// global.navigator.credentials = {
//   create: jest.fn().mockImplementation(() => {
//     return new Promise((resolve) => {
//       resolve({
//         rawId: new Uint8Array(26).fill(0).buffer,
//         response: {
//           attestationObject: new Uint8Array(26).fill(0).buffer,
//           clientDataJSON: new Uint8Array(26).fill(0).buffer,
//         },
//         getClientExtensionResults: jest.fn(),
//         type: 'public-key',
//       });
//     });
//   }),
//   get: jest.fn().mockImplementation(() => {
//     return new Promise((resolve) => {
//       resolve({
//         rawId: new Uint8Array(26).fill(0).buffer,
//         response: {
//           authenticatorData: new Uint8Array(26).fill(0).buffer,
//           clientDataJSON: new Uint8Array(26).fill(0).buffer,
//           signature: new Uint8Array(26).fill(0).buffer,
//           userHandle: null,
//         },
//         getClientExtensionResults: jest.fn(),
//         type: 'public-key',
//       });
//     });
//   }),
// };

describe('[PREDICATES]', () => {
  let auth: IUserAuth;
  let provider: Provider;

  beforeAll(async () => {
    provider = await Provider.create('http://localhost:4000/v1/graphql');
  }, 20 * 1000);

  test('Sent a transaction without API calls', async () => {
    const user = accounts['FULL'].privateKey;
    const wallet = Wallet.fromPrivateKey(user, provider);
    const signers = [
      accounts['USER_1'].address,
      accounts['USER_2'].address,
      accounts['USER_3'].address,
      '0x9962da540401d92e1d06a61a0a41428f64cadf5d821b2f7f51b9c18dfdc7d2e2',
    ];

    // const tx_id =
    //   '0000000000000000000000000000000000000000000000000000000000000001';
    const tx_id =
      '361928fde57834469c1f2d9bbf858cda73d431e6b1b04149d6836a7c2e890410';
    const script = ScriptAbi__factory.createInstance(wallet);
    const invocationScope = await script.functions.main(`0x${tx_id}`).txParams({
      gasLimit: 10000000,
      maxFee: 1000000,
    });
    const txRequest = await invocationScope.getTransactionRequest();

    const priv = secp256r1.utils.randomPrivateKey();
    const publicKey = secp256r1.getPublicKey(priv, false);

    // console.log('public address', publicKey);
    // console.log('public address', sha256(publicKey));

    const dataJSON = `{"type":"webauthn.get","challenge":"${tx_id}","origin":"http://localhost:5173","crossOrigin":false}`;
    const mockReponseWebAuthn = {
      authenticatorData:
        '0x49960de5880e8c687434170f6476605b8fe4aeb9a28632c7995cf3ba831d97631d00000000',
      clientDataJSON: new TextEncoder().encode(dataJSON),
    };

    // '{"type":"webauthn.get","challenge":"","origin":"http://localhost:5173","crossOrigin":false}'
    const clientHash = sha256(mockReponseWebAuthn.clientDataJSON);
    const digest = sha256(
      concat([mockReponseWebAuthn.authenticatorData, clientHash]),
    );
    const [preffixText, suffixText] = dataJSON.split(tx_id);
    const prefix = hexlify(new TextEncoder().encode(preffixText));
    const suffix = hexlify(new TextEncoder().encode(suffixText));
    // console.log(prefix);
    // console.log(suffix);
    const sig = secp256r1.sign(digest.slice(2), priv);
    const _sig = concat([
      bigintToUint8Array(sig.r),
      Uint8Array.from([sig.recovery]),
      bigintToUint8Array(sig.s),
    ]);
    // console.log(clientHash);
    // console.log(digest);
    // ...getSignature(publicKey, response.signature, digest),
    console.dir(getSignature(publicKey.toString(), _sig, arrayify(digest)), {
      depth: null,
    });
    // console.log(prefix);
    // console.log(suffix);

    const signature = hexlify(
      encode({
        type: SignatureType.WebAuthn,
        // signature: sig,
        signature:
          '0xdd8db7ea99c0eadfbbd0ab280c67ff0313693f8205c9af0bebfe08e64dc8b7900e23bf1da7fe5068ae9b0a2adc5af8d1695dc61aa78ae297e5021ca57b6332e6',
        prefix,
        suffix,
        authData:
          '0x49960de5880e8c687434170f6476605b8fe4aeb9a28632c7995cf3ba831d97631d00000000',
      }),
    );
    txRequest.witnesses = [signature];
    // console.log(hexlify(bufferFromString(txid, 'utf-8'))); // <----
    // const hash = hashMessage(`0x${tx_id}`);
    // console.log('hash', hash);
    // console.log(Signer.recoverAddress(hash, _signature).toB256());
    const txCost = await wallet.provider.getTransactionCost(txRequest);
    await wallet.fund(txRequest, txCost);

    try {
      const callResult = await wallet.provider.dryRun(txRequest, {
        utxoValidation: false,
        estimateTxDependencies: false,
      });

      console.dir(callResult.receipts, { depth: null });
    } catch (e) {
      console.log(e.message);
    }

    // const vault = new Vault({
    //   abi: JSON.stringify(PredicateAbi__factory.abi),
    //   bytecode: PredicateAbi__factory.bin,
    //   provider: provider,
    //   configurable: {
    //     SIGNATURES_COUNT: 2,
    //     SIGNERS: makeSigners(signers),
    //     HASH_PREDICATE: makeHashPredicate(),
    //     network: provider.url,
    //     chainId: provider.getChainId(),
    //   },
    // });

    // await sendPredicateCoins(
    //   vault,
    //   bn.parseUnits('0.1'),
    //   assets['ETH'],
    //   wallet,
    // );

    // const tx = DEFAULT_TRANSACTION_PAYLOAD(accounts['STORE'].address);

    // const tx_id =
    //   '361928fde57834469c1f2d9bbf858cda73d431e6b1b04149d6836a7c2e890410';

    // const mockReponseWebAuthn = {
    //   authenticatorData: new Uint8Array(30).fill(1),
    //   clientDataJSON: new TextEncoder().encode(
    //     '{"type":"webauthn.get","challenge":"361928fde57834469c1f2d9bbf858cda73d431e6b1b04149d6836a7c2e890410","origin":"https://safe.bako.global","crossOrigin":false}',
    //   ),
    // };
    // const clientHash = sha256(mockReponseWebAuthn.clientDataJSON);
    // const digest = await sha256(
    //   concat([mockReponseWebAuthn.authenticatorData, clientHash]),
    // );
    // console.log(digest);

    // const transaction = await vault.BakoSafeIncludeTransaction(tx);
    // transaction.witnesses = [
    //   encode({
    //     type: SignatureType.Fuel,
    //     signature: await signin(tx_id, 'USER_2'),
    //   }),
    //   encode({
    //     type: SignatureType.WebAuthn,
    //     signature:
    //       '0xdd8db7ea99c0eadfbbd0ab280c67ff0313693f8205c9af0bebfe08e64dc8b7900e23bf1da7fe5068ae9b0a2adc5af8d1695dc61aa78ae297e5021ca57b6332e6',
    //     prefix:
    //       '0x7b2274797065223a22776562617574686e2e676574222c226368616c6c656e6765223a22',
    //     suffix:
    //       '0x222c226f726967696e223a22687474703a2f2f6c6f63616c686f73743a35313733222c2263726f73734f726967696e223a66616c73657d',
    //     authData:
    //       '0x49960de5880e8c687434170f6476605b8fe4aeb9a28632c7995cf3ba831d97631d00000000',
    //   }),
    // ];

    // const result = await transaction.send().then(async (tx) => {
    //   if ('wait' in tx) {
    //     return await tx.wait();
    //   }
    //   return {
    //     status: TransactionStatus.failure,
    //   };
    // });

    // console.log(result);

    // expect(result.status).toBe(TransactionStatus.success);
  });
});
