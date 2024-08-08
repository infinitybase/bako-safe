
library;

use std::{
  b512::B512,
  bytes::Bytes,
  hash::*,
  alloc::alloc,
};

use ::entities::{
  WebAuthnHeader,
};

use ::utilities::{
  write_bytes,
};

/// Get the WebAuthn digest

///     - params:
///         - webauthn: the WebAuthn struct
///         - ptr_data: the pointer to the signature
///         - tx_id_bytes: the transaction id

///     - process:
///         - recreate the message signed by webauthn.io
///         [https://webauthn.io/]

///     - returns: the digest(message)
pub fn get_webauthn_digest(
    webauthn: WebAuthnHeader,
    ptr_data: raw_ptr,
    tx_id_bytes: Bytes,
) -> b256 {
    let tx_id_size = __size_of::<B512>();
    // Sizes
    let size_payload: u64 = webauthn.prefix_size + tx_id_size + webauthn.suffix_size;
    // Data ptr
    let ptr_data_suffix = ptr_data.add_uint_offset(webauthn.prefix_size);
    let ptr_data_msg = ptr_data_suffix.add_uint_offset(webauthn.suffix_size);
    // Bytes ptr
    let ptr_bytes = alloc::<u8>(size_payload + __size_of::<b256>());
    let ptr_bytes_tx = ptr_bytes.add_uint_offset(webauthn.prefix_size);
    let ptr_bytes_suffix = ptr_bytes_tx.add_uint_offset(tx_id_size);
    let ptr_bytes_msg = ptr_bytes_suffix.add_uint_offset(webauthn.suffix_size);
    let ptr_bytes_hash = ptr_bytes_msg.add_uint_offset(webauthn.message_data_size);
    // Write bytes
    write_bytes(ptr_bytes, ptr_data, webauthn.suffix_size);
    write_bytes(ptr_bytes_tx, tx_id_bytes.ptr(), tx_id_size);
    write_bytes(ptr_bytes_suffix, ptr_data_suffix, webauthn.suffix_size);
    write_bytes(ptr_bytes_msg, ptr_data_msg, webauthn.suffix_size);

    let mut digest = b256::zero();
    let mut digest2 = b256::zero();
    asm(
        ptr_bytes: ptr_bytes,
        ptr_hash: ptr_bytes_hash,
        ptr_msg: ptr_bytes_msg,
        size_auth: size_payload,
        size_hash: webauthn.message_data_size + __size_of::<b256>(),
        digest: digest,
        digest2: digest2,
    ) {
        s256 digest2 ptr_bytes size_auth;
        s256 ptr_hash ptr_bytes size_auth;
        s256 digest ptr_msg size_hash;
    };
    log(digest);
    log(digest2);
    return digest;
}