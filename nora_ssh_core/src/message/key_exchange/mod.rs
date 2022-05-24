mod ecdh;

pub use ecdh::{
    KeyExchangeEcdhInit, KeyExchangeEcdhInitParseError, KeyExchangeEcdhReply,
    KeyExchangeEcdhReplyParseError,
};

use crate::data::{
    make_bool, make_raw, make_string2, name_list, split,
    InvalidNameList, NameList,
};

pub struct KeyExchangeInit<'a> {
    pub cookie: &'a [u8; 16],
    pub kex_algorithms: NameList<'a>,
    pub server_host_key_algorithms: NameList<'a>,
    pub encryption_algorithms_client_to_server: NameList<'a>,
    pub encryption_algorithms_server_to_client: NameList<'a>,
    pub mac_algorithms_client_to_server: NameList<'a>,
    pub mac_algorithms_server_to_client: NameList<'a>,
    pub compression_algorithms_client_to_server: NameList<'a>,
    pub compression_algorithms_server_to_client: NameList<'a>,
    pub languages_client_to_server: NameList<'a>,
    pub languages_server_to_client: NameList<'a>,
    pub first_kex_packet_follows: bool,
}

impl<'a> KeyExchangeInit<'a> {
    pub(super) fn parse(data: &'a [u8]) -> Result<Self, KeyExchangeInitParseError> {
        // Skip cookie
        let split = |data, i| split(data, i).ok_or(KeyExchangeInitParseError::Truncated);
        let name_list = |data| {
            name_list(data)
                .ok_or(KeyExchangeInitParseError::Truncated)
                .and_then(|(list, data)| {
                    list.map(|list| (list, data))
                        .map_err(KeyExchangeInitParseError::InvalidNameList)
                })
        };
        let (cookie, data) = split(data, 16)?;
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
            cookie: cookie.try_into().unwrap(),
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

    pub(super) fn serialize(&self, buf: &mut [u8]) -> Option<usize> {
        let (a, buf) = make_raw(buf, self.cookie)?;
        let (b, buf) = make_string2(buf, self.kex_algorithms.into())?;
        let (c, buf) = make_string2(buf, self.server_host_key_algorithms.into())?;
        let (d, buf) = make_string2(buf, self.encryption_algorithms_client_to_server.into())?;
        let (e, buf) = make_string2(buf, self.encryption_algorithms_server_to_client.into())?;
        let (f, buf) = make_string2(buf, self.mac_algorithms_client_to_server.into())?;
        let (g, buf) = make_string2(buf, self.mac_algorithms_server_to_client.into())?;
        let (h, buf) = make_string2(buf, self.compression_algorithms_client_to_server.into())?;
        let (i, buf) = make_string2(buf, self.compression_algorithms_server_to_client.into())?;
        let (j, buf) = make_string2(buf, self.languages_client_to_server.into())?;
        let (k, buf) = make_string2(buf, self.languages_server_to_client.into())?;
        let (l, _) = make_bool(buf, self.first_kex_packet_follows)?;
        Some(a + b + c + d + e + f + g + h + i + j + k + l)
    }
}

#[derive(Debug)]
pub enum KeyExchangeInitParseError {
    Truncated,
    NoTrailingZero,
    Unread,
    InvalidNameList(InvalidNameList),
}

pub struct NewKeys;

impl NewKeys {
    pub(super) fn parse(data: &[u8]) -> Result<Self, NewKeysParseError> {
        (data.len() == 0)
            .then(|| Self)
            .ok_or(NewKeysParseError::Unread)
    }

    pub(super) fn serialize(&self, _buf: &mut [u8]) -> Option<usize> {
        Some(0)
    }
}

#[derive(Debug)]
pub enum NewKeysParseError {
    Unread,
}
