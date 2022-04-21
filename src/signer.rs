use crate::constants::field;
use crate::Result;

#[derive(Debug, PartialEq, Clone)]
pub struct RBHeader<T> {
    buffer: T,
}

impl<T: AsRef<[u8]>> RBHeader<T> {
    /// Imbue a raw octet buffer with rustBoot structure.
    pub fn new_unchecked(buffer: T) -> RBHeader<T> {
        RBHeader { buffer }
    }

    /// Shorthand for a combination of [new_unchecked].
    ///
    /// [new_unchecked]: #method.new_unchecked
    pub fn new_checked(buffer: T) -> Result<RBHeader<T>> {
        let packet = Self::new_unchecked(buffer);
        Ok(packet)
    }

    /// Returns a ref to the underlying buffer.
    pub fn inner_ref(&self) -> &T {
        &self.buffer
    }
}

impl<T: AsRef<[u8]> + AsMut<[u8]>> RBHeader<T> {
    /// Set the magic key field.
    #[inline]
    pub fn set_magic_key(&mut self, value: u32) {
        let data = self.buffer.as_mut();
        data[field::MAGIC_KEY.start] = ((value >> 24) & 0xFF) as u8;
        data[field::MAGIC_KEY.start + 1] = ((value >> 16) & 0xFF) as u8;
        data[field::MAGIC_KEY.start + 2] = ((value >> 8) & 0xFF) as u8;
        data[field::MAGIC_KEY.start + 3] = (value & 0xFF) as u8;
    }

    /// Set the magic key size field.
    #[inline]
    pub fn set_magic_key_size(&mut self, value: u32) {
        let data = self.buffer.as_mut();
        data[field::MAGIC_KEY_SIZE.start] = ((value >> 24) & 0xFF) as u8;
        data[field::MAGIC_KEY_SIZE.start + 1] = ((value >> 16) & 0xFF) as u8;
        data[field::MAGIC_KEY_SIZE.start + 2] = ((value >> 8) & 0xFF) as u8;
        data[field::MAGIC_KEY_SIZE.start + 3] = (value & 0xFF) as u8;
    }

    /// Set the version, type, and length field.
    #[inline]
    pub fn set_version_type_len(&mut self, value: u32) {
        let data = self.buffer.as_mut();
        data[field::VERSION_TYPE_LEN.start] = ((value >> 24) & 0xFF) as u8;
        data[field::VERSION_TYPE_LEN.start + 1] = ((value >> 16) & 0xFF) as u8;
        data[field::VERSION_TYPE_LEN.start + 2] = ((value >> 8) & 0xFF) as u8;
        data[field::VERSION_TYPE_LEN.start + 3] = (value & 0xFF) as u8;
    }

    /// Set the version value and padding field.
    #[inline]
    pub fn set_version_value(&mut self, value: &[u8]) -> Result<()> {
        let len = value.len();
        {
            let data = self.buffer.as_mut();
            data[field::VERSION_VALUE.start..field::VERSION_VALUE.start + len]
                .copy_from_slice(value);
        }

        if (len % 4) == 0 {
            let data = self.buffer.as_mut();
            let pad_len = 8 - len;
            let padding_offset = field::VERSION_VALUE.start + len;
            let padding = [0xff; 4];
            Ok(data[padding_offset..padding_offset + pad_len].copy_from_slice(&padding[..pad_len]))
        } else {
            let data = self.buffer.as_mut();
            let pad_len = 8 - len;
            let padding_offset = field::VERSION_VALUE.start + len;
            let padding = [0xff; 8];
            Ok(data[padding_offset..padding_offset + pad_len].copy_from_slice(&padding[..pad_len]))
        }
    }

    /// Set the padding feild
    #[inline]
    pub fn set_timestamp_type_len(&mut self, value: u32) {
        let data = self.buffer.as_mut();
        data[field::TIMESTAMP_LEN_TYPE.start] = ((value >> 24) & 0xFF) as u8;
        data[field::TIMESTAMP_LEN_TYPE.start + 1] = ((value >> 16) & 0xFF) as u8;
        data[field::TIMESTAMP_LEN_TYPE.start + 2] = ((value >> 8) & 0xFF) as u8;
        data[field::TIMESTAMP_LEN_TYPE.start + 3] = (value & 0xFF) as u8
    }

    /// Set the time stamp feild
    #[inline]
    pub fn set_timestamp_value(&mut self, value: &[u8]) -> Result<()> {
        let len = value.len();
        let data = self.buffer.as_mut();
        Ok(
            data[field::TIMESTAMP_VALUE.start..field::TIMESTAMP_VALUE.start + len]
                .copy_from_slice(value),
        )
    }

    /// Set the Image type and length feild
    #[inline]
    pub fn set_image_type_len(&mut self, value: u32) {
        let data = self.buffer.as_mut();
        data[field::IMAGE_TYPE_LEN.start] = ((value >> 24) & 0xFF) as u8;
        data[field::IMAGE_TYPE_LEN.start + 1] = ((value >> 16) & 0xFF) as u8;
        data[field::IMAGE_TYPE_LEN.start + 2] = ((value >> 8) & 0xFF) as u8;
        data[field::IMAGE_TYPE_LEN.start + 3] = (value & 0xFF) as u8
    }

    /// Set the Image Value feild
    #[inline]
    pub fn set_image_value(&mut self, value: &[u8]) -> Result<()> {
        let len = value.len();
        {
            let data = self.buffer.as_mut();
            data[field::IMAGE_VALUE.start..field::IMAGE_VALUE.start + len].copy_from_slice(value);
        }

        if (len % 4) == 0 {
            let data = self.buffer.as_mut();
            let pad_len = 8 - len;
            let padding_offset = field::IMAGE_VALUE.start + len;
            let padding = [0xff; 6];
            Ok(data[padding_offset..padding_offset + pad_len].copy_from_slice(&padding[..pad_len]))
        } else {
            let data = self.buffer.as_mut();
            let pad_len = 8 - len;
            let padding_offset = field::IMAGE_VALUE.start + len;
            let padding = [0xff; 8];
            Ok(data[padding_offset..padding_offset + pad_len].copy_from_slice(&padding[..pad_len]))
        }
    }

    /// Set the digest type and length feild
    #[inline]
    pub fn set_digest_type_len(&mut self, value: u32) {
        let data = self.buffer.as_mut();
        data[field::DIGEST_TYPE_LEN.start] = ((value >> 24) & 0xFF) as u8;
        data[field::DIGEST_TYPE_LEN.start + 1] = ((value >> 16) & 0xFF) as u8;
        data[field::DIGEST_TYPE_LEN.start + 2] = ((value >> 8) & 0xFF) as u8;
        data[field::DIGEST_TYPE_LEN.start + 3] = (value & 0xFF) as u8
    }

    /// Set the time stamp feild
    #[inline]
    pub fn set_sha256_digest_value(&mut self, value: &[u8]) -> Result<()> {
        let len = value.len();
        let data = self.buffer.as_mut();
        Ok(
            data[field::SHA256_DIGEST.start..field::SHA256_DIGEST.start + len]
                .copy_from_slice(value),
        )
    }

    /// Set the Public Key type and length feild
    #[inline]
    pub fn set_pubkey_type_len(&mut self, value: u32) {
        let data = self.buffer.as_mut();
        data[field::PUBKEY_TYPE_LEN.start] = ((value >> 24) & 0xFF) as u8;
        data[field::PUBKEY_TYPE_LEN.start + 1] = ((value >> 16) & 0xFF) as u8;
        data[field::PUBKEY_TYPE_LEN.start + 2] = ((value >> 8) & 0xFF) as u8;
        data[field::PUBKEY_TYPE_LEN.start + 3] = (value & 0xFF) as u8
    }

    /// Set the time stamp feild
    #[inline]
    pub fn set_pubkey_digest_value(&mut self, value: &[u8]) -> Result<()> {
        let len = value.len();
        let data = self.buffer.as_mut();
        Ok(
            data[field::PUBKEY_DIGEST_VALUE.start..field::PUBKEY_DIGEST_VALUE.start + len]
                .copy_from_slice(value),
        )
    }

    /// Set the Public Key type and length feild
    #[inline]
    pub fn set_signature_type_len(&mut self, value: u32) {
        let data = self.buffer.as_mut();
        data[field::SIGNATURE_TYPE_LEN.start] = ((value >> 24) & 0xFF) as u8;
        data[field::SIGNATURE_TYPE_LEN.start + 1] = ((value >> 16) & 0xFF) as u8;
        data[field::SIGNATURE_TYPE_LEN.start + 2] = ((value >> 8) & 0xFF) as u8;
        data[field::SIGNATURE_TYPE_LEN.start + 3] = (value & 0xFF) as u8
    }

    /// Set the time stamp feild
    #[inline]
    pub fn set_signatue_value(&mut self, value: &[u8]) -> Result<()> {
        let len = value.len();
        {
            let data = self.buffer.as_mut();
            data[field::SIGNATURE_VALUE.start..field::SIGNATURE_VALUE.start + len]
                .copy_from_slice(value);
        }

        if (len % 4) == 0 {
            let data = self.buffer.as_mut();
            let pad_len = 134 - len;
            let padding_offset = field::SIGNATURE_VALUE.start + len;
            let padding = [0xff; 134];
            Ok(data[padding_offset..padding_offset + pad_len].copy_from_slice(&padding[..pad_len]))
        } else {
            let data = self.buffer.as_mut();
            let pad_len = 134 - len;
            let padding_offset = field::SIGNATURE_VALUE.start + len;
            let padding = [0xff; 134];
            Ok(data[padding_offset..padding_offset + pad_len].copy_from_slice(&padding[..pad_len]))
        }
    }

    /// Set the padding feild.
    // #[inline]
    // pub fn set_padding(&mut self, pad: &[u8]) -> Result<()> {
    //     let len = pad.len();
    //     let data = self.buffer.as_mut();

    //     // if len == 4 {
    //     //     Ok(data[field::PAD1.start..field::PAD1.start + len].copy_from_slice(pad))
    //     // } else if len == 6 {
    //     //     Ok(data[field::PAD2.start..field::PAD2.start + len].copy_from_slice(pad))
    //     // } else {
    //     // Ok(data[field::PAD3.start..field::PAD3.start + len].copy_from_slice(pad))
    //     // }
    // }

    /// Set the Image Value feild
    #[inline]
    pub fn set_end_of_header(&mut self, value: u16) {
        let data = self.buffer.as_mut();
        data[field::EOH.start] = ((value >> 8) & 0xFF) as u8;
        data[field::EOH.start + 1] = (value & 0xFF) as u8
    }

    // /// Set the padding feild
    // #[inline]
    // pub fn set_padding(&mut self, padding: u32) {
    //     let data = self.buffer.as_mut();
    //     data[field::PADDING.start] = ((padding >> 24) & 0xFF) as u8;
    //     data[field::PADDING.start + 1] = ((padding >> 16) & 0xFF) as u8;
    //     data[field::PADDING.start + 2] = ((padding >> 8) & 0xFF) as u8;
    //     data[field::PADDING.start + 3] = (padding & 0xFF) as u8
    // }
}

// #[derive(Debug, PartialEq, Clone)]
// pub struct RBPacket<T> {
//     pub packet: RBHeader<T>,
// }

// impl<T: AsRef<[u8]> + AsMut<[u8]>> RBPacket<T> {
//     /// Construct a new RBPacket packet struct.
//     pub fn new(packet: RBHeader<T>) -> RBPacket<T> {
//         RBPacket { packet }
//     }

//     pub fn new_rbpacket() -> Result<RBPacket<[u8; 256]>> {
//         let rbpacket_buffer = RBHeader::new_checked([0; 256])?;
//         Ok(RBPacket::new(rbpacket_buffer))
//     }
// }
