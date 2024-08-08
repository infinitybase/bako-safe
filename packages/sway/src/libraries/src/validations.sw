library;

use std::{
  constants::ZERO_B256,
};
use ::constants::{
  INVALID_ADDRESS,
  MAX_SIGNERS,
  PREFIX_BAKO_SIG,
};


/// Verify if the public_key is duplicated in the verified_signatures

///    - process:
///        - iterate over the verified_signatures
///        - if the public_key is equal to any of the verified_signatures, return
///        - if the public_key is not equal to any of the verified_signatures, add it to the verified_signatures

///     - params:
///        - public_key: the public key to verify
///        - verified_signatures: the list of verified signatures

///     - returns: void
pub fn check_duplicated_signers(
  public_key: Address,
  ref mut verified_signatures: Vec::<Address>,
) {
  let mut i = 0;

  if Address::from(INVALID_ADDRESS) == public_key { //stop condition
    return;
  }

  while i < verified_signatures.len() {
    if verified_signatures.get(i).unwrap() == public_key {
      return;
    }
    

    i += 1;
  }
  verified_signatures.push(public_key);
}

/// Verify if the public_key is in the signers list

///    - process:
///        - iterate over the signers
///        - if the public_key is equal to any of the signers, return the public_key
///        - if the public_key is not equal to any of the signers, return INVALID_ADDRESS

///     - params:
///        - public_key: the public key to verify
///        - signers: the list of signers

///     - returns: the public_key if it exists in the signers list, INVALID_ADDRESS otherwise
pub fn check_signer_exists(
  public_key: Address,
  signers: [b256; 10],
) -> Address {
  let mut i = 0;

  while i < MAX_SIGNERS {
    if Address::from(signers[i]) == public_key {
      return public_key;
    }
    if Address::from(signers[i]) == Address::from(ZERO_B256) {
      return Address::from(INVALID_ADDRESS);
    }

    i += 1;
  }

  return Address::from(INVALID_ADDRESS);
}


/// Verify if the prefix is correct

///    - process:
///        - verify if the prefix is equal to the BAKO_SIG

///     - params:
///        - witness_ptr: the pointer to the witness

///     - returns: true if the prefix is correct, false otherwise
pub fn verify_prefix(witness_ptr: raw_ptr) -> bool {
    asm(
        prefix: PREFIX_BAKO_SIG,
        witness_ptr: witness_ptr,
        size: 4,
        r1,
    ) {
        meq r1 witness_ptr prefix size;
        r1: bool
    }
}