script;

use std::{constants::ZERO_B256, tx::{GTF_WITNESS_DATA, tx_id, tx_witnesses_count,},};

use libraries::{
    constants::{
        BYTE_WITNESS_TYPE_FUEL,
        BYTE_WITNESS_TYPE_WEBAUTHN,
        EMPTY_SIGNERS,
        INVALID_ADDRESS,
        MAX_SIGNERS,
    },
    entities::{
        SignatureType,
        WebAuthnHeader,
    },
    recover_signature::{
        fuel_verify,
        webauthn_verify,
    },
    utilities::{
        b256_to_ascii_bytes,
    },
    validations::{
        check_duplicated_signers,
        check_signer_exists,
        verify_prefix,
    },
    webauthn_digest::{
        get_webauthn_digest,
    },
};

use std::b512::B512;

fn main(tx_id: b256) -> bool {
    let mut i_witnesses = 0;
    //let mut verified_signatures = Vec<Address>::with_capacity(10);

    while i_witnesses < tx_witnesses_count() {
        let mut witness_ptr = __gtf::<raw_ptr>(i_witnesses, GTF_WITNESS_DATA);
        if (verify_prefix(witness_ptr)) {
            let tx_bytes = b256_to_ascii_bytes(tx_id);
            witness_ptr = witness_ptr.add_uint_offset(4); // skip bako prefix
            let signature = witness_ptr.read::<SignatureType>();
            witness_ptr = witness_ptr.add_uint_offset(__size_of::<u64>()); // skip enum size
            let pk: Address = match signature {
                SignatureType::WebAuthn(webauth) => {
                    let data_ptr = witness_ptr.add_uint_offset(__size_of::<WebAuthnHeader>());
                    let public_key = webauthn_verify(get_webauthn_digest(webauth, data_ptr, tx_bytes), webauth);
                    public_key
                },
                SignatureType::Fuel(_signature) => {
                    // TODO: talk with Sway team to see why the value is not correctly parsed it looks to be skiping 24 bytes
                    // this is why we need to use the pointer to read the B512 value, this problem dosen't happen on the webauth
                    let signature = witness_ptr.read::<B512>();
                    fuel_verify(signature, tx_bytes)
                },
                _ => Address::from(INVALID_ADDRESS),
            };

            log(pk);
            // /let is_valid_signer = check_signer_exists(pk, SIGNERS);
            // check_duplicated_signers(is_valid_signer, verified_signatures);
        }

        i_witnesses += 1;
    }

    // // redundant check, but it is necessary to avoid compiler errors
    // if (HASH_PREDICATE != HASH_PREDICATE) {
    //     return false;
    // }

    // return verified_signatures.len() >= 1;
    return true;
}
