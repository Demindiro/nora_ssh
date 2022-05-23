//! Chacha20Poly1305 as described in OpenSSH's `PROTOCOL.chacha20poly1305`

// FIXME ChaCha20Legacy internally uses a 32 bit counter while we need a 64-bit counter to be
// truly compatible.

use super::{BlockSize, Cipher, Error};
use crate::key_exchange::{Direction, KeyMaterial};
use chacha20::{
    cipher::{StreamCipher, StreamCipherSeekCore},
    ChaCha20Legacy, Key, LegacyNonce,
};
use digest::{crypto_common::KeyIvInit, Digest, OutputSizeUser};
use poly1305::{universal_hash::NewUniversalHash, Tag};

const TAG_SIZE: usize = 16;

pub struct ChaCha20Poly1305 {
    key_length: Key,
    key_data: Key,
    counter: u64,
}

impl ChaCha20Poly1305 {
    pub const NAME: &'static str = "chacha20-poly1305@openssh.com";

    pub fn from_key_material<D: Digest + OutputSizeUser>(
        mat: &KeyMaterial<D>,
        dir: Direction,
        counter: u64,
    ) -> Self {
        let mut key = [[0; 32]; 2]; // TODO use D::OutputSize as soon as we can
        mat.encryption_key(dir, &mut key);
        Self {
            key_length: *Key::from_slice(&key[1]),
            key_data: *Key::from_slice(&key[0]),
            counter,
        }
    }

    fn nonce(&self) -> LegacyNonce {
        *LegacyNonce::from_slice(&self.counter.to_be_bytes())
    }

    fn compute_tag(&self, data: &[u8]) -> Tag {
        let mut mac_key = poly1305::Key::default();
        chacha20::ChaCha20Legacy::new(&self.key_data, &self.nonce()).apply_keystream(&mut mac_key);
        let mac_key = poly1305::Key::from_slice(&mac_key);
        let mac = poly1305::Poly1305::new(&mac_key);
        mac.compute_unpadded(&data)
    }

    fn authenticate(&self, data: &[u8]) -> bool {
        let (data, tag) = data.split_at(data.len() - TAG_SIZE);
        self.compute_tag(data) == Tag::new(<[u8; TAG_SIZE]>::try_from(tag).unwrap().into())
    }

    fn apply_data(&self, data: &mut [u8]) {
        let mut cipher = chacha20::ChaCha20LegacyCore::new(&self.key_data, &self.nonce());
        cipher.set_block_pos(1);
        chacha20::cipher::StreamCipherCoreWrapper::from_core(cipher).apply_keystream(data);
    }
}

impl Cipher for ChaCha20Poly1305 {
    fn decrypt_length(&mut self, mut length: [u8; 4]) -> Result<[u8; 4], Error> {
        ChaCha20Legacy::new(&self.key_length, &self.nonce()).apply_keystream(&mut length);
        Ok(length)
    }

    fn decrypt_data<'a>(&mut self, data: &'a mut [u8]) -> Result<(), Error> {
        // Always verify **before** decrypting to avoid oracle attacks
        if self.authenticate(data) {
            let l = data.len() - TAG_SIZE;
            self.apply_data(&mut data[4..l]);
            // 2^70 is 1 ZiB worth of data, which a single session will *never* reach in practice
            self.counter += 1;
            Ok(())
        } else {
            Err(Error)
        }
    }

    fn encrypt(&mut self, data: &mut [u8]) {
        let (data, tag) = data.split_at_mut(data.len() - TAG_SIZE);
        let (len, payload) = data.split_at_mut(4);
        ChaCha20Legacy::new(&self.key_length, &self.nonce()).apply_keystream(len);
        self.apply_data(payload);
        tag.copy_from_slice(&self.compute_tag(data).into_bytes());
        // Ditto
        self.counter += 1;
    }

    fn tag_size(&self) -> usize {
        TAG_SIZE
    }

    fn block_size(&self) -> BlockSize {
        BlockSize::B8
    }
}
