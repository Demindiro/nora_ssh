use super::Message;
use crate::data::{make_pos_mpint, make_string, name_list, parse_string};

pub struct KeyExchangeEcdhInit<'a> {
    client_ephermal_public_key: &'a [u8; 32],
}

impl<'a> KeyExchangeEcdhInit<'a> {
    pub fn parse(data: &'a [u8]) -> Result<Self, KeyExchangeEcdhInitParseError> {
        if data.len() != 4 + 32 {
            Err(KeyExchangeEcdhInitParseError::BadLength)
        } else {
            Ok(Self {
                client_ephermal_public_key: parse_string(data).unwrap().try_into().unwrap(),
            })
        }
    }

    pub fn into_public_key(self) -> x25519_dalek::PublicKey {
        x25519_dalek::PublicKey::from(*self.client_ephermal_public_key)
    }
}

#[derive(Debug)]
pub enum KeyExchangeEcdhInitParseError {
    Truncated,
    BadLength,
    Unread,
}

#[derive(Debug)]
pub struct KeyExchangeEcdhReply<'a> {
    server_public_key: &'a [u8; 32],
    server_ephermal_public_key: &'a [u8; 32],
    exchange_hash_signature: &'a [u8; 64],
}

impl<'a> KeyExchangeEcdhReply<'a> {
    pub fn new_payload(
        buf: &'a mut [u8],
        server_public_key: &'a ecdsa::VerifyingKey<p256::NistP256>,
        server_ephermal_public_key: &'a x25519_dalek::PublicKey,
        exchange_hash_signature: &'a ecdsa::Signature<p256::NistP256>,
    ) -> (&'a mut [u8], &'a mut [u8]) {
        let mut keybuf = [0; 128];
        let mut blob = [0; 128];

        let (ty, b) = buf.split_first_mut().unwrap();
        *ty = Message::KEX_ECDH_REPLY;

        let (_, b) = Self::server_host_key(b, server_public_key);

        let (_, b) = make_string(b, server_ephermal_public_key.as_bytes()).unwrap();

        // signature
        let kb = &mut keybuf[..];
        let (_, kb) = make_string(kb, b"ecdsa-sha2-nistp256").unwrap();
        let (r, s) = &exchange_hash_signature.split_bytes();
        let i = 0 + make_pos_mpint(&mut blob[0..], r).unwrap();
        let i = i + make_pos_mpint(&mut blob[i..], s).unwrap();
        let (_, kb) = make_string(kb, &blob[..i]).unwrap();
        let kb = kb.len();
        let (_, b) = make_string(b, &keybuf[..keybuf.len() - kb]).unwrap();

        let b = b.len();
        buf.split_at_mut(buf.len() - b)
    }

    pub fn server_host_key<'i>(
        buf: &'i mut [u8],
        key: &ecdsa::VerifyingKey<p256::NistP256>,
    ) -> (&'i mut [u8], &'i mut [u8]) {
        let mut keybuf = [0; 128];
        let kb = &mut keybuf;
        let (_, kb) = make_string(kb, b"ecdsa-sha2-nistp256").unwrap();
        let (_, kb) = make_string(kb, b"nistp256").unwrap();
        // OpenSSH doesn't like compressed points.
        let (_, kb) = make_string(kb, key.to_encoded_point(false).as_bytes()).unwrap();
        let kb = kb.len();
        let (_, b) = make_string(buf, &keybuf[..keybuf.len() - kb]).unwrap();
        let b = b.len();
        buf.split_at_mut(buf.len() - b)
    }
}
