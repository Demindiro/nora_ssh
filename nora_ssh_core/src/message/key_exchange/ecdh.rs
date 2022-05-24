use super::Message;
use crate::data::{
    make_pos_mpint, make_pos_mpint2, make_string, make_string2, make_uint32, name_list,
    parse_string, parse_string3,
};

pub struct KeyExchangeEcdhInit<'a> {
    pub client_ephermal_public_key: &'a [u8],
}

impl<'a> KeyExchangeEcdhInit<'a> {
    pub(in super::super) fn parse(data: &'a [u8]) -> Result<Self, KeyExchangeEcdhInitParseError> {
        let (client_ephermal_public_key, data) =
            parse_string3(data).ok_or(KeyExchangeEcdhInitParseError::Truncated)?;
        data.is_empty()
            .then(|| Self {
                client_ephermal_public_key,
            })
            .ok_or(KeyExchangeEcdhInitParseError::Unread)
    }

    pub(in super::super) fn serialize(&self, buf: &mut [u8]) -> Option<usize> {
        let (a, _) = make_string2(buf, self.client_ephermal_public_key)?;
        Some(a)
    }
}

#[derive(Debug)]
pub enum KeyExchangeEcdhInitParseError {
    Truncated,
    Unread,
}

pub struct KeyExchangeEcdhReply<'a> {
    pub server_public_key: Key<'a>,
    pub server_ephermal_public_key: &'a [u8],
    pub exchange_hash_signature: Signature<'a>,
}

impl<'a> KeyExchangeEcdhReply<'a> {
    pub(in super::super) fn parse(data: &'a [u8]) -> Result<Self, KeyExchangeEcdhReplyParseError> {
        let parse_str = |d| parse_string3(d).ok_or(KeyExchangeEcdhReplyParseError::Truncated);
        let (server_public_key, data) = parse_str(data)?;
        let server_public_key =
            Key::parse(server_public_key).ok_or(KeyExchangeEcdhReplyParseError::BadData)?;
        let (server_ephermal_public_key, data) = parse_str(data)?;
        let (exchange_hash_signature, data) = parse_str(data)?;
        let exchange_hash_signature = Signature::parse(exchange_hash_signature)
            .ok_or(KeyExchangeEcdhReplyParseError::BadData)?;
        data.is_empty()
            .then(|| Self {
                server_public_key,
                server_ephermal_public_key,
                exchange_hash_signature,
            })
            .ok_or(KeyExchangeEcdhReplyParseError::Unread)
    }

    pub(in super::super) fn serialize(&self, buf: &mut [u8]) -> Option<usize> {
        let (a, buf) = self.server_public_key.serialize(buf)?;
        let (b, buf) = make_string2(buf, self.server_ephermal_public_key)?;
        let (c, _) = self.exchange_hash_signature.serialize(buf)?;
        Some(a + b + c)
    }
}

pub struct Key<'a> {
    pub name: &'a [u8],
    pub blob: KeyBlob<'a>,
}

impl<'a> Key<'a> {
    fn parse(data: &'a [u8]) -> Option<Self> {
        let (name, data) = parse_string3(data)?;
        let blob = KeyBlob::parse(data)?;
        data.is_empty().then(|| Self { name, blob })
    }

    fn serialize<'i>(&self, buf: &'i mut [u8]) -> Option<(usize, &'i mut [u8])> {
        (buf.len() >= 4).then(|| ())?;
        let (lenbuf, buf) = buf.split_at_mut(4);
        let (a, buf) = make_string2(buf, self.name)?;
        let (b, buf) = self.blob.serialize(buf)?;
        make_uint32(lenbuf, (a + b).try_into().unwrap()).unwrap();
        Some((4 + a + b, buf))
    }
}

pub struct KeyBlob<'a> {
    pub identifier: &'a [u8],
    pub q: &'a [u8],
}

impl<'a> KeyBlob<'a> {
    fn parse(data: &'a [u8]) -> Option<Self> {
        let (identifier, data) = parse_string3(data)?;
        let (q, data) = parse_string3(data)?;
        data.is_empty().then(|| Self { identifier, q })
    }

    fn serialize<'i>(&self, buf: &'i mut [u8]) -> Option<(usize, &'i mut [u8])> {
        let (a, buf) = make_string2(buf, b"nistp256")?;
        let (b, buf) = make_string2(buf, self.q)?;
        Some((a + b, buf))
    }
}

pub struct Signature<'a> {
    pub name: &'a [u8],
    pub blob: SignatureBlob<'a>,
}

impl<'a> Signature<'a> {
    fn parse(data: &'a [u8]) -> Option<Self> {
        let (name, data) = parse_string3(data)?;
        let (blob, data) = parse_string3(data)?;
        let blob = SignatureBlob::parse(blob)?;
        data.is_empty().then(|| Self { name, blob })
    }

    fn serialize<'i>(&self, buf: &'i mut [u8]) -> Option<(usize, &'i mut [u8])> {
        let (a, buf) = make_string2(buf, self.name)?;
        let (b, buf) = self.blob.serialize(buf)?;
        Some((a + b, buf))
    }
}

pub struct SignatureBlob<'a> {
    pub r: &'a [u8],
    pub s: &'a [u8],
}

impl<'a> SignatureBlob<'a> {
    fn parse(data: &'a [u8]) -> Option<Self> {
        let (r, data) = parse_string3(data)?;
        let (s, data) = parse_string3(data)?;
        data.is_empty().then(|| Self { r, s })
    }

    fn serialize<'i>(&self, buf: &'i mut [u8]) -> Option<(usize, &'i mut [u8])> {
        let (a, buf) = make_pos_mpint2(buf, self.r)?;
        let (b, buf) = make_pos_mpint2(buf, self.s)?;
        Some((a + b, buf))
    }
}

#[derive(Debug)]
pub enum KeyExchangeEcdhReplyParseError {
    Truncated,
    Unread,
    BadData,
}
