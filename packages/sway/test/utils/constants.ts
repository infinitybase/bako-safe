export const ERROR_DUPLICATED_WITNESSES =
  'FuelError: Invalid transaction data: PredicateVerificationFailed(Panic(PredicateReturnedNonOne))';

export const PRIVATE_KEY =
  '0xa449b1ffee0e2205fa924c6740cc48b3b473aa28587df6dab12abc245d1f5298';
export const GAS_LIMIT = 10000000;
export const MAX_FEE = 100000000;
export const GAS_PRICE = 1;

export const CHAIN_URL = 'http://localhost:4000/v1/graphql';

// transactions signed by webauthn are not posible to be signed an tested by code
export const WEBAUTHN = {
  tx_id: '0x361928fde57834469c1f2d9bbf858cda73d431e6b1b04149d6836a7c2e890410',
  address: '0x9962da540401d92e1d06a61a0a41428f64cadf5d821b2f7f51b9c18dfdc7d2e2',
  signature:
    '0x0000000000000000dd8db7ea99c0eadfbbd0ab280c67ff0313693f8205c9af0bebfe08e64dc8b7900e23bf1da7fe5068ae9b0a2adc5af8d1695dc61aa78ae297e5021ca57b6332e60000000000000024000000000000003700000000000000257b2274797065223a22776562617574686e2e676574222c226368616c6c656e6765223a22222c226f726967696e223a22687474703a2f2f6c6f63616c686f73743a35313733222c2263726f73734f726967696e223a66616c73657d49960de5880e8c687434170f6476605b8fe4aeb9a28632c7995cf3ba831d97631d00000000',
};
