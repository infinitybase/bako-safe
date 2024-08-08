library;

use std::bytes::Bytes;

use ::constants::{
    ASCII_MAP,
};

pub fn b256_to_ascii_bytes(val: b256) -> Bytes {
    let bytes = Bytes::from(val);
    let mut ascii_bytes = Bytes::with_capacity(64);
    let mut idx = 0;

    while idx < 32 {
        let b = bytes.get(idx).unwrap();
        ascii_bytes.push(ASCII_MAP[(b >> 4).as_u64()]);
        ascii_bytes.push(ASCII_MAP[(b & 15).as_u64()]);
	    idx = idx + 1;
    }

    ascii_bytes
}

pub fn write_bytes(target_ptr: raw_ptr, src_ptr: raw_ptr, size: u64) {
    asm(target_ptr: target_ptr, src_ptr: src_ptr, size: size) {
        mcp target_ptr src_ptr size;
    };
}

pub fn hash_tx_id(value: Bytes) -> b256 {
  let mut digest = b256::zero();
  asm(value: value.ptr(), size: value.len(), r1: digest) {
    s256 r1 value size;
  };
  digest
}