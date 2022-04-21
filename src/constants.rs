#![allow(warnings)]

pub mod field {
    #![allow(non_snake_case)]

    use core::ops::{Range, RangeFrom};

    pub type Field = Range<usize>;
    pub type Rest = RangeFrom<usize>;

    pub const RBHEADER_LEN: u8 = 255;

    pub const MAGIC_KEY: Field = 0..4;
    pub const MAGIC_KEY_SIZE: Field = 4..8;
    pub const VERSION_TYPE_LEN: Field = 8..12;
    pub const VERSION_VALUE: Field = 12..20;
    // pub const PAD1: Field = 16..24;
    pub const TIMESTAMP_LEN_TYPE: Field = 20..24;
    pub const TIMESTAMP_VALUE: Field = 24..32;
    pub const IMAGE_TYPE_LEN: Field = 32..36;
    pub const IMAGE_VALUE: Field = 36..44;
    // pub const PAD2: Field = 38..44;
    pub const DIGEST_TYPE_LEN: Field = 44..48;
    pub const SHA256_DIGEST: Field = 48..80;
    pub const PUBKEY_TYPE_LEN: Field = 80..84;
    pub const PUBKEY_DIGEST_VALUE: Field = 84..116;
    pub const SIGNATURE_TYPE_LEN: Field = 116..120;
    pub const SIGNATURE_VALUE: Field = 120..254;
    // pub const PAD3: Field = 184..254;
    pub const EOH: Field = 254..256;
}
