script;

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
    FuelHeader,
  },
  constants::{
      MAX_SIGNERS,
      EMPTY_SIGNERS,
      INVALID_ADDRESS,
      BYTE_WITNESS_TYPE_FUEL,
      BYTE_WITNESS_TYPE_WEBAUTHN,
  }
};

use std::b512::B512;

fn main(tx_id: b256, address: b256) -> bool {
    let mut witness_ptr = __gtf::<raw_ptr>(0, GTF_WITNESS_DATA);
    let tx_bytes = b256_to_ascii_bytes(tx_id);
    
    if (verify_prefix(witness_ptr)) {
        // skip bako prefix
        witness_ptr = witness_ptr.add_uint_offset(4);
        let signature = witness_ptr.read::<SignatureType>();
        // skip enum size
        witness_ptr = witness_ptr.add_uint_offset(__size_of::<u64>());
        
        let pk = match signature {
          SignatureType::WebAuthn(webauthn) => {
            
            let data_ptr = witness_ptr.add_uint_offset(__size_of::<WebAuthnHeader>());
            let private_key = webauthn_verify(
                get_webauthn_digest(webauthn, data_ptr, tx_bytes),
                webauthn,
            );
            private_key
          },
          SignatureType::Fuel(_signature) => {
            // TODO: talk with Sway team to see why the value is not correctly parsed it looks to be skiping 24 bytes
            // this is why we need to use the pointer to read the B512 value, this problem dosen't happen on the webauth
            let signature = witness_ptr.read::<B512>();
            fuel_verify(signature, tx_bytes)
          },
          _ => Address::from(INVALID_ADDRESS),
        };
        return pk == Address::from(address);
    }
    false
}