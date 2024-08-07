library;

use std::{
  b512::B512,
  hash::*,
  bytes::Bytes,
  result::Result,
  ecr::{
    ec_recover_address, 
    ec_recover_address_r1
  },
  tx::{
    GTF_WITNESS_DATA,
    tx_witness_data,
  },
};
use ::utilities::{
  hash_tx_id,
};
use ::entities::{
  WebAuthnHeader
};
use ::webauthn_digest::{
  get_webauthn_digest,
};
use ::constants::{
  INVALID_ADDRESS,
};

/// Verify a signature using the FUEL curve [Secp256k1]

///     - params: 
///         - signature: the signature to verify
///         - tx_hash: the hash of the transaction

///     - returns: the address of the signer
pub fn fuel_verify(signature: B512, tx_bytes: Bytes) -> Address {
  let tx_fuel = hash_tx_id(tx_bytes);
  match ec_recover_address(signature, tx_fuel) {
    Result::Ok(pub_key_sig) => pub_key_sig,
    _ => Address::from(INVALID_ADDRESS),
  }

}

/// Verify a signature using the secp256r1 curve [Secp256r1]

///     - params:
///         - signature: the signature to verify
///         - digest: the digest of the message

///     - returns: the address of the signer
pub fn webauthn_verify(digest: b256, webauthn: WebAuthnHeader) -> Address {
    match ec_recover_address_r1(webauthn.signature, digest) {
        Result::Ok(address) => address,
        _ => Address::from(INVALID_ADDRESS),
    }
}