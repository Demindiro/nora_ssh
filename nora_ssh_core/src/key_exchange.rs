use crate::data::make_pos_mpint;
use core::marker::PhantomData;
use digest::{Digest, OutputSizeUser};

/// All supported key exchange algorithms.
pub const ALGORITHM_NAMES: &'static [&'static str] = &["curve25519-sha256"];

#[derive(Clone, Copy)]
pub enum Direction {
	ClientToServer,
	ServerToClient,
}

pub struct KeyMaterial<D: Digest + OutputSizeUser> {
	secret: [u8; 4 + 1 + 32],
	secret_len: usize,
	hash: [u8; 32],
	_marker: PhantomData<D>,
}

impl<D: Digest + OutputSizeUser> KeyMaterial<D> {
	pub fn new(secret: [u8; 32], hash: [u8; 32]) -> Self {
		let mut secret_buf = [0; 4 + 1 + 32];
		let secret_len = make_pos_mpint(&mut secret_buf, &secret).unwrap();
		Self { secret: secret_buf, secret_len, hash, _marker: PhantomData }
	}
}

// TODO generic_const_exprs is unstable, so just hardcode for now.
const OUTPUT_SIZE: usize = 32;

macro_rules! gen {
	($f:ident[$c:literal]) => {
		pub fn $f<'a>(&self, dir: Direction, out: &'a mut [[u8; OUTPUT_SIZE]]) -> &'a [u8] {
			self.gen(
				match dir {
					Direction::ClientToServer => $c,
					Direction::ServerToClient => $c + 1,
				},
				out,
			)
		}
	};
}

impl<D: Digest + OutputSizeUser> KeyMaterial<D> {
	fn digest_k1<'a>(&self, x: u8) -> [u8; OUTPUT_SIZE] {
		let session_id = &self.hash;
		// HASH(K || H || X || session_id)
		D::new()
			.chain_update(&self.secret[..self.secret_len])
			.chain_update(&self.hash)
			.chain_update(&[x])
			.chain_update(session_id)
			.finalize()[..]
			.try_into()
			.unwrap()
	}

	fn digest_kn<'a>(&self, keys: &[[u8; OUTPUT_SIZE]]) -> [u8; OUTPUT_SIZE] {
		// HASH(K || H || K1 || K2 ... || K(n-1))
		let mut digest = D::new()
			.chain_update(&self.secret[..self.secret_len])
			.chain_update(&self.hash);
		for k in keys {
			digest.update(k)
		}
		digest.finalize()[..].try_into().unwrap()
	}

	fn gen<'a>(&self, x: u8, out: &'a mut [[u8; OUTPUT_SIZE]]) -> &'a [u8] {
		out[0] = self.digest_k1(x);
		for i in 1..out.len() {
			let k = self.digest_kn(&out[..i]);
			out[i] = k;
		}
		// SAFETY: representing &[[u8; _]] as &[u8] is valid.
		unsafe { out.align_to().1 }
	}

	gen!(initial_iv[b'A']);
	gen!(encryption_key[b'C']);
	gen!(integrity_key[b'E']);
}
