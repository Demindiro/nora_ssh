pub mod channel;
mod key_exchange;
mod service;
pub mod userauth;

pub use channel::Channel;
pub use key_exchange::{
    KeyExchangeEcdhInit, KeyExchangeEcdhInitParseError, KeyExchangeEcdhReply, KeyExchangeInit,
    KeyExchangeInitParseError, NewKeys, NewKeysParseError,
};
pub use service::{
    ParseServiceAcceptError, ParseServiceRequestError, ServiceAccept, ServiceRequest,
};
pub use userauth::UserAuth;

use crate::data::parse_string;
use core::ops::RangeInclusive;

pub enum Message<'a> {
    Disconnect(Disconnect<'a>),
    KeyExchangeInit(KeyExchangeInit<'a>),
    KeyExchangeEcdhInit(KeyExchangeEcdhInit<'a>),
    NewKeys(NewKeys),
    ServiceRequest(ServiceRequest<'a>),
    ServiceAccept(ServiceAccept<'a>),
    UserAuth(UserAuth<'a>),
    Channel(Channel<'a>),
}

impl<'a> Message<'a> {
    const DISCONNECT: u8 = 1;
    const IGNORE: u8 = 2;
    const UNIMPLEMENTED: u8 = 3;
    const DEBUG: u8 = 4;
    const SERVICE_REQUEST: u8 = 5;
    const SERVICE_ACCEPT: u8 = 6;

    const KEXINIT: u8 = 20;
    const NEWKEYS: u8 = 21;

    const KEX_ECDH_INIT: u8 = 30;
    const KEX_ECDH_REPLY: u8 = 31;

    const USERAUTH: RangeInclusive<u8> = 50..=79;
    const CHANNEL: RangeInclusive<u8> = 90..=127;

    pub fn parse(data: &'a [u8]) -> Result<Self, MessageParseError> {
        match *data.get(0).ok_or(MessageParseError::NoMessageType)? {
            Self::DISCONNECT => Disconnect::parse(&data[1..])
                .map(Self::Disconnect)
                .map_err(MessageParseError::Disconnect),
            Self::IGNORE => todo!(),
            Self::UNIMPLEMENTED => todo!(),
            Self::DEBUG => todo!(),
            Self::SERVICE_REQUEST => ServiceRequest::parse(&data[1..])
                .map(Self::ServiceRequest)
                .map_err(MessageParseError::ServiceRequest),
            Self::SERVICE_ACCEPT => ServiceAccept::parse(&data[1..])
                .map(Self::ServiceAccept)
                .map_err(MessageParseError::ServiceAccept),
            Self::KEXINIT => KeyExchangeInit::parse(&data[1..])
                .map(Self::KeyExchangeInit)
                .map_err(MessageParseError::KeyExchangeInit),
            Self::NEWKEYS => NewKeys::parse(&data[1..])
                .map(Self::NewKeys)
                .map_err(MessageParseError::NewKeys),
            Self::KEX_ECDH_INIT => KeyExchangeEcdhInit::parse(&data[1..])
                .map(Self::KeyExchangeEcdhInit)
                .map_err(MessageParseError::KeyExchangeEcdhInit),
            Self::KEX_ECDH_REPLY => todo!(),
            t if Self::USERAUTH.contains(&t) => UserAuth::parse(t, &data[1..])
                .map(Self::UserAuth)
                .map_err(MessageParseError::UserAuth),
            t if Self::CHANNEL.contains(&t) => Channel::parse(t, &data[1..])
                .map(Self::Channel)
                .map_err(MessageParseError::Channel),
            ty => Err(MessageParseError::UnknownMessageType(ty)),
        }
    }

    pub fn send<R, F>(&self, mut send: F) -> Result<(), R>
    where
        F: FnMut(&[u8]) -> Result<(), R>,
    {
        match self {
            Self::Disconnect(_) => todo!(),
            Self::KeyExchangeInit(_) => todo!(),
            Self::KeyExchangeEcdhInit(_) => todo!(),
            Self::NewKeys(NewKeys) => send(&[Self::NEWKEYS]),
            Self::ServiceRequest(s) => {
                send(&[Self::SERVICE_REQUEST])?;
                s.send(send)
            }
            Self::ServiceAccept(s) => {
                send(&[Self::SERVICE_ACCEPT])?;
                s.send(send)
            }
            Self::UserAuth(ua) => unimplemented!("deprecate send"),
            Self::Channel(ch) => ch.send(send),
        }
    }

    pub fn serialize<'s>(&self, buf: &'s mut [u8]) -> Result<&'s mut [u8], Full> {
        match self {
            Self::UserAuth(ua) => ua.serialize(buf),
            _ => {
                let mut i = 0;
                return self
                    .send(|d| {
                        buf.get_mut(i..i + d.len())
                            .map(|w| {
                                w.copy_from_slice(d);
                                i += d.len();
                            })
                            .ok_or(Full)
                    })
                    .map(|()| &mut buf[..i]);
            }
        }
        .map(|i| &mut buf[..i])
        .ok_or(Full)
    }
}

#[derive(Debug)]
pub enum MessageParseError {
    NoMessageType,
    UnknownMessageType(u8),
    Disconnect(ParseDisconnectError),
    KeyExchangeInit(KeyExchangeInitParseError),
    KeyExchangeEcdhInit(KeyExchangeEcdhInitParseError),
    NewKeys(NewKeysParseError),
    ServiceRequest(ParseServiceRequestError),
    ServiceAccept(ParseServiceAcceptError),
    UserAuth(userauth::ParseError),
    Channel(channel::ParseError),
}

#[derive(Debug)]
pub struct Full;

macro_rules! msg {
    ($v:ident -> $f:ident, $g:ident) => {
        impl Message<'_> {
            pub fn $f(&self) -> Option<&$v> {
                match self {
                    Self::$v(v) => Some(v),
                    _ => None,
                }
            }

            pub fn $g(self) -> Option<$v> {
                match self {
                    Self::$v(v) => Some(v),
                    _ => None,
                }
            }
        }

        impl From<$v> for Message<'_> {
            fn from(v: $v) -> Self {
                Self::$v(v)
            }
        }
    };
    ('a $v:ident -> $f:ident, $g:ident) => {
        impl<'a> Message<'a> {
            pub fn $f(&self) -> Option<&$v<'a>> {
                match self {
                    Self::$v(v) => Some(v),
                    _ => None,
                }
            }

            pub fn $g(self) -> Option<$v<'a>> {
                match self {
                    Self::$v(v) => Some(v),
                    _ => None,
                }
            }
        }

        impl<'a> From<$v<'a>> for Message<'a> {
            fn from(v: $v<'a>) -> Self {
                Self::$v(v)
            }
        }
    };
}

msg!('a Disconnect -> as_disconnect, into_disconnect);
msg!('a KeyExchangeInit -> as_kex_init, into_kex_init);
msg!('a KeyExchangeEcdhInit -> as_kex_ecdh_init, into_kex_ecdh_init);
msg!(NewKeys -> as_new_keys, into_new_keys);
msg!('a ServiceRequest -> as_service_request, into_service_request);
msg!('a ServiceAccept -> as_service_accept, into_service_accept);
msg!('a UserAuth -> as_user_auth, into_user_auth);
msg!('a Channel -> as_channel, into_channel);

pub struct Disconnect<'a> {
    pub reason: u32,
    pub description: &'a [u8],
    pub language: &'a [u8],
}

impl<'a> Disconnect<'a> {
    fn parse(data: &'a [u8]) -> Result<Self, ParseDisconnectError> {
        let reason = data.get(..4).ok_or(ParseDisconnectError::BadLength)?;
        let description = parse_string(&data[4..]).ok_or(ParseDisconnectError::BadLength)?;
        let data = &data[4 + 4 + description.len()..];
        let language = parse_string(data).ok_or(ParseDisconnectError::BadLength)?;
        if data.len() != 4 + language.len() {
            Err(ParseDisconnectError::BadLength)
        } else {
            Ok(Self {
                reason: u32::from_be_bytes(reason.try_into().unwrap()),
                description,
                language,
            })
        }
    }
}

#[derive(Debug)]
pub enum ParseDisconnectError {
    BadLength,
}
