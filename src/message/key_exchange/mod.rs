mod ecdh;

pub use ecdh::{KeyExchangeEcdhInit, KeyExchangeEcdhInitParseError, KeyExchangeEcdhReply};

use super::Message;
use crate::data::{make_pos_mpint, make_string, name_list, parse_string, split};

pub struct KeyExchangeInit<'a> {
    kex_algorithms: &'a [u8],
    server_host_key_algorithms: &'a [u8],
    encryption_algorithms_client_to_server: &'a [u8],
    encryption_algorithms_server_to_client: &'a [u8],
    mac_algorithms_client_to_server: &'a [u8],
    mac_algorithms_server_to_client: &'a [u8],
    compression_algorithms_client_to_server: &'a [u8],
    compression_algorithms_server_to_client: &'a [u8],
    languages_client_to_server: &'a [u8],
    languages_server_to_client: &'a [u8],
    first_kex_packet_follows: bool,
}

macro_rules! name_list {
    ($v:ident) => {
        pub fn $v(&self) -> impl Iterator<Item = &'a [u8]> {
            self.$v.split(|&c| c == b',')
        }
    };
}

impl<'a> KeyExchangeInit<'a> {
    pub fn parse(data: &'a [u8]) -> Result<Self, KeyExchangeInitParseError> {
        // Skip cookie
        let split = |data, i| split(data, i).ok_or(KeyExchangeInitParseError::Truncated);
        let name_list = |data| name_list(data).ok_or(KeyExchangeInitParseError::Truncated);
        let (_cookie, data) = split(data, 16)?;
        let (kex_algorithms, data) = name_list(data)?;
        let (server_host_key_algorithms, data) = name_list(data)?;
        let (encryption_algorithms_client_to_server, data) = name_list(data)?;
        let (encryption_algorithms_server_to_client, data) = name_list(data)?;
        let (mac_algorithms_client_to_server, data) = name_list(data)?;
        let (mac_algorithms_server_to_client, data) = name_list(data)?;
        let (compression_algorithms_client_to_server, data) = name_list(data)?;
        let (compression_algorithms_server_to_client, data) = name_list(data)?;
        let (languages_client_to_server, data) = name_list(data)?;
        let (languages_server_to_client, data) = name_list(data)?;
        // TODO it seems OpenSSH doesn't send this field?
        let (first_kex_packet_follows, data) = split(data, 1)?;
        let (zero, data) = split(data, 4)?;
        if zero != &[0; 4] {
            return Err(KeyExchangeInitParseError::NoTrailingZero);
        }
        if !data.is_empty() {
            return Err(KeyExchangeInitParseError::Unread);
        }
        Ok(Self {
            kex_algorithms,
            server_host_key_algorithms,
            encryption_algorithms_client_to_server,
            encryption_algorithms_server_to_client,
            mac_algorithms_client_to_server,
            mac_algorithms_server_to_client,
            compression_algorithms_client_to_server,
            compression_algorithms_server_to_client,
            languages_client_to_server,
            languages_server_to_client,
            first_kex_packet_follows: first_kex_packet_follows[0] != 0,
        })
    }

    fn send<R, F>(&self, mut send: F) -> Result<(), R>
    where
        F: FnMut(&[u8]) -> Result<(), R>,
    {
        let mut send = |data: &[u8]| {
            send(&u32::try_from(data.len()).unwrap().to_be_bytes())?;
            send(data)
        };
        // FIXME cookie has to be randomized
        send(&[Message::KEXINIT])?;
        send(&[0; 16])?;
        send(self.kex_algorithms)?;
        send(self.server_host_key_algorithms)?;
        send(self.encryption_algorithms_client_to_server)?;
        send(self.encryption_algorithms_server_to_client)?;
        send(self.mac_algorithms_client_to_server)?;
        send(self.mac_algorithms_server_to_client)?;
        send(self.compression_algorithms_client_to_server)?;
        send(self.compression_algorithms_server_to_client)?;
        send(self.languages_client_to_server)?;
        send(self.languages_server_to_client)?;
        send(&[u8::from(self.first_kex_packet_follows), 0, 0, 0, 0])
    }

    pub fn new_payload<'i>(
        buf: &mut [u8],
        kex_algorithms: impl Iterator<Item = &'i str>,
        server_host_key_algorithms: impl Iterator<Item = &'i str>,
        encryption_algorithms_client_to_server: impl Iterator<Item = &'i str>,
        encryption_algorithms_server_to_client: impl Iterator<Item = &'i str>,
        mac_algorithms_client_to_server: impl Iterator<Item = &'i str>,
        mac_algorithms_server_to_client: impl Iterator<Item = &'i str>,
        compression_algorithms_client_to_server: impl Iterator<Item = &'i str>,
        compression_algorithms_server_to_client: impl Iterator<Item = &'i str>,
        languages_client_to_server: impl Iterator<Item = &'i str>,
        languages_server_to_client: impl Iterator<Item = &'i str>,
    ) -> (&mut [u8], &mut [u8]) {
        fn name_list<'j>(buf: &mut [u8], iter: impl Iterator<Item = &'j str>, none: bool) -> usize {
            let (len, buf) = buf.split_at_mut(4);
            let mut i = 0;
            let mut push = |b| {
                buf[i] = b;
                i += 1;
            };
            for (i, s) in iter.enumerate() {
                (i != 0).then(|| push(b','));
                s.bytes().for_each(|c| push(c));
            }
            if none && i == 0 {
                buf[..4].copy_from_slice(b"none");
                i = 4;
            }
            len.copy_from_slice(&u32::try_from(i).unwrap().to_be_bytes());
            4 + i
        }
        buf[0] = Message::KEXINIT;
        let i = 17; // message type + cookie
        let i = name_list(&mut buf[i..], kex_algorithms, true) + i;
        let i = name_list(&mut buf[i..], server_host_key_algorithms, true) + i;
        let i = name_list(&mut buf[i..], encryption_algorithms_client_to_server, true) + i;
        let i = name_list(&mut buf[i..], encryption_algorithms_server_to_client, true) + i;
        let i = name_list(&mut buf[i..], mac_algorithms_client_to_server, true) + i;
        let i = name_list(&mut buf[i..], mac_algorithms_server_to_client, true) + i;
        let i = name_list(&mut buf[i..], compression_algorithms_client_to_server, true) + i;
        let i = name_list(&mut buf[i..], compression_algorithms_server_to_client, true) + i;
        let i = name_list(&mut buf[i..], languages_client_to_server, false) + i;
        let i = name_list(&mut buf[i..], languages_server_to_client, false) + i;
        buf[i..i + 5].copy_from_slice(&[0; 5]); // guess + zero
        buf.split_at_mut(i + 5)
    }

    name_list!(kex_algorithms);
    name_list!(server_host_key_algorithms);
    name_list!(encryption_algorithms_client_to_server);
    name_list!(encryption_algorithms_server_to_client);
    name_list!(mac_algorithms_client_to_server);
    name_list!(mac_algorithms_server_to_client);
    name_list!(compression_algorithms_client_to_server);
    name_list!(compression_algorithms_server_to_client);
    name_list!(languages_client_to_server);
    name_list!(languages_server_to_client);
}

#[derive(Debug)]
pub enum KeyExchangeInitParseError {
    Truncated,
    NoTrailingZero,
    Unread,
}

pub struct NewKeys;

impl NewKeys {
    pub fn parse(data: &[u8]) -> Result<Self, NewKeysParseError> {
        (data.len() == 0)
            .then(|| Self)
            .ok_or(NewKeysParseError::Unread)
    }
}

#[derive(Debug)]
pub enum NewKeysParseError {
    Unread,
}
