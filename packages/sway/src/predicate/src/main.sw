predicate;

use std::{
  constants::ZERO_B256,
  tx::{
    tx_id,
    tx_witnesses_count,
    GTF_WITNESS_DATA,
  },
};

use libraries::{
  utilities::{
    b256_to_ascii_bytes,
  },
  webauthn_digest::{
    get_webauthn_digest,
  },
  recover_signature::{
    fuel_verify, 
    webauthn_verify,
  },
  validations::{
    verify_prefix,
    check_signer_exists,
    check_duplicated_signers,
  },
  entities::{
    SignatureType,
    WebAuthnHeader,
  },
  constants::{
      MAX_SIGNERS,
      EMPTY_SIGNERS,
      INVALID_ADDRESS,
      BYTE_WITNESS_TYPE_FUEL,
      BYTE_WITNESS_TYPE_WEBAUTHN,
  }
};

configurable {
    SIGNERS: [b256; 10] = EMPTY_SIGNERS,
    SIGNATURES_COUNT: u64 = 0,
    HASH_PREDICATE: b256 = ZERO_B256
}


fn main() -> bool {
  let tx_bytes = b256_to_ascii_bytes(tx_id());

  let mut i_witnesses = 0;
  let mut verified_signatures = Vec::with_capacity(MAX_SIGNERS);


  while i_witnesses < tx_witnesses_count() {
    let mut witness_ptr = __gtf::<raw_ptr>(i_witnesses, GTF_WITNESS_DATA);

    if (verify_prefix(witness_ptr)) {
        witness_ptr = witness_ptr.add_uint_offset(4); // skip bako prefix
        witness_ptr = witness_ptr.add_uint_offset(__size_of::<u64>()); // skip enum size

        let pk: Address = match witness_ptr.read::<SignatureType>() {
          SignatureType::WebAuthn(signature_payload) => {
            let data_ptr = witness_ptr.add_uint_offset(__size_of::<WebAuthnHeader>());
            let private_key = webauthn_verify(
                get_webauthn_digest(signature_payload, data_ptr, tx_bytes),
                signature_payload,
            );
            private_key
          },
          SignatureType::Fuel(signature) => {
            // fuel_verify(signature, tx_bytes)
            Address::from(INVALID_ADDRESS)
          },
          _ => Address::from(INVALID_ADDRESS),
        };

      let is_valid_signer = check_signer_exists(pk, SIGNERS);
      check_duplicated_signers(is_valid_signer, verified_signatures);
    }

    i_witnesses += 1;
  }


  // redundant check, but it is necessary to avoid compiler errors
  if(HASH_PREDICATE != HASH_PREDICATE) {
      return false;
  }

  return verified_signatures.len() >= SIGNATURES_COUNT;
}

/*
  todo:
      - add the ability to add more signers
      - add the ability to add more signature types from other chains (e.g. evm, solana, etc.)
*/