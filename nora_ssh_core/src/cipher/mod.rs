mod chacha20poly1305;

use crate::packet::BlockSize;
pub use chacha20poly1305::ChaCha20Poly1305;

/// The names of all supported ciphers.
pub const CIPHER_NAMES: &'static [&'static str] = &[ChaCha20Poly1305::NAME];

pub trait Cipher {
	fn decrypt_length(&mut self, length: [u8; 4]) -> Result<[u8; 4], Error>;

	fn decrypt_data<'a>(&mut self, data: &'a mut [u8]) -> Result<(), Error>;

	fn encrypt(&mut self, data: &mut [u8]);

	fn tag_size(&self) -> usize;

	fn block_size(&self) -> BlockSize;
}

/// Generic error type. No information is included to avoid oracle attacks.
#[derive(Debug)]
pub struct Error;
