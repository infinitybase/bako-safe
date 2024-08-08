library;

use std::b512::B512;

pub enum SignatureType {
    WebAuthn: WebAuthnHeader,
    Fuel: B512,
}

pub struct WebAuthnHeader {
    pub signature: B512,
    pub prefix_size: u64,
    pub suffix_size: u64,
    pub message_data_size: u64,
}
