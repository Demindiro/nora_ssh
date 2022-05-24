use rand::{CryptoRng, RngCore};

pub struct Packet<'a> {
    data: &'a mut [u8],
}

impl<'a> Packet<'a> {
    pub fn packet_len(&self) -> usize {
        u32::from_be_bytes(*self.packet_len_bytes())
            .try_into()
            .unwrap()
    }

    pub fn packet_len_bytes(&self) -> &[u8; 4] {
        self.data[..4].try_into().unwrap()
    }

    pub fn packet_len_bytes_mut(&mut self) -> &mut [u8; 4] {
        self.data[..4].as_mut().try_into().unwrap()
    }

    pub fn packet_bytes(&self) -> &[u8] {
        &self.data[4..4 + self.packet_len()]
    }

    pub fn packet_bytes_mut(&mut self) -> &mut [u8] {
        let l = self.packet_len();
        &mut self.data[4..4 + l]
    }

    pub fn padding_len(&self) -> usize {
        self.data[4].into()
    }

    pub fn payload_len(&self) -> usize {
        self.packet_len() - self.padding_len() - 1
    }

    pub fn payload(&self) -> &[u8] {
        &self.data[5..5 + self.payload_len()]
    }

    pub fn payload_mut(&mut self) -> &mut [u8] {
        let l = self.payload_len();
        &mut self.data[5..5 + l]
    }

    pub fn into_payload(self) -> &'a mut [u8] {
        let l = self.payload_len();
        &mut self.data[5..5 + l]
    }

    pub fn as_raw(&self) -> &[u8] {
        &self.data[..4 + self.packet_len()]
    }

    pub fn as_raw_mut(&mut self) -> &mut [u8] {
        let l = self.packet_len();
        &mut self.data[..4 + l]
    }

    pub fn into_raw(self, with_extra: usize) -> &'a mut [u8] {
        let l = self.packet_len();
        &mut self.data[..4 + l + with_extra]
    }

    pub fn wrap_raw(
        data: &'a mut [u8],
        pad_with_packet_length: bool,
        block_size: BlockSize,
    ) -> Result<Self, WrapRawError> {
        let slf = Self { data };
        let offt = usize::from(pad_with_packet_length) * 4;
        if (slf.packet_len() + offt) % block_size.to_usize() != 0 {
            Err(WrapRawError::BadAlignment)
        } else if slf.padding_len() >= slf.packet_len() {
            Err(WrapRawError::PaddingTooLarge)
        } else {
            Ok(slf)
        }
    }

    pub fn wrap<R, F>(
        buf: &'a mut [u8],
        block_size: BlockSize,
        pad_with_packet_length: bool,
        make_payload: F,
        mut rng: R,
    ) -> Self
    where
        F: FnOnce(&mut [u8]) -> usize,
        R: CryptoRng + RngCore,
    {
        let block_size = block_size.to_usize();
        let offset = usize::from(!pad_with_packet_length) * 4;
        let payload_len = make_payload(&mut buf[4 + 1..]);
        let total_len = ((4 + 1 + payload_len + block_size - 1) & !(block_size - 1)) + offset;
        let mut packet_len = total_len - 4;
        let mut padding_len = packet_len - payload_len - 1;
        if padding_len < 4 {
            padding_len += block_size;
            packet_len += block_size;
        }
        buf[..4].copy_from_slice(&u32::try_from(packet_len).unwrap().to_be_bytes());
        buf[4] = padding_len.try_into().unwrap();
        rng.fill_bytes(&mut buf[4 + 1 + payload_len..][..padding_len]);
        Self { data: buf }
    }
}

#[derive(Clone, Copy)]
pub enum BlockSize {
    B8,
    B16,
    B32,
    B64,
}

impl BlockSize {
    fn to_usize(self) -> usize {
        match self {
            BlockSize::B8 => 8,
            BlockSize::B16 => 16,
            BlockSize::B32 => 32,
            BlockSize::B64 => 64,
        }
    }
}

#[derive(Debug)]
pub enum WrapRawError {
    BadAlignment,
    PaddingTooLarge,
}
