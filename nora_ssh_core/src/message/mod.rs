pub mod channel;
pub mod key_exchange;
mod service;
pub mod userauth;

pub use channel::Channel;
pub use key_exchange::{
    KeyExchangeEcdhInit, KeyExchangeEcdhInitParseError, KeyExchangeEcdhReply,
    KeyExchangeEcdhReplyParseError, KeyExchangeInit, KeyExchangeInitParseError, NewKeys,
    NewKeysParseError,
};
pub use service::{
    ParseServiceAcceptError, ParseServiceRequestError, ServiceAccept, ServiceRequest,
};
pub use userauth::UserAuth;

use crate::data::{
    make_bool, make_string2, make_uint32, parse_bool, parse_string, parse_string3, parse_uint32,
};
use core::ops::RangeInclusive;

pub enum Message<'a> {
    Disconnect(Disconnect<'a>),
    Ignore(Ignore<'a>),
    Unimplemented(Unimplemented),
    Debug(Debug<'a>),
    KeyExchangeInit(KeyExchangeInit<'a>),
    KeyExchangeEcdhInit(KeyExchangeEcdhInit<'a>),
    KeyExchangeEcdhReply(KeyExchangeEcdhReply<'a>),
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
            Self::IGNORE => Ignore::parse(&data[1..])
                .map(Self::Ignore)
                .map_err(MessageParseError::Ignore),
            Self::UNIMPLEMENTED => Unimplemented::parse(&data[1..])
                .map(Self::Unimplemented)
                .map_err(MessageParseError::Unimplemented),
            Self::DEBUG => Debug::parse(&data[1..])
                .map(Self::Debug)
                .map_err(MessageParseError::Debug),
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
            Self::KEX_ECDH_REPLY => KeyExchangeEcdhReply::parse(&data[1..])
                .map(Self::KeyExchangeEcdhReply)
                .map_err(MessageParseError::KeyExchangeEcdhReply),
            t if Self::USERAUTH.contains(&t) => UserAuth::parse(t, &data[1..])
                .map(Self::UserAuth)
                .map_err(MessageParseError::UserAuth),
            t if Self::CHANNEL.contains(&t) => Channel::parse(t, &data[1..])
                .map(Self::Channel)
                .map_err(MessageParseError::Channel),
            ty => Err(MessageParseError::UnknownMessageType(ty)),
        }
    }

    pub fn serialize<'s>(&self, buf: &'s mut [u8]) -> Option<(&'s mut [u8], &'s mut [u8])> {
        fn f<F: FnOnce(&mut [u8]) -> Option<usize>>(ty: u8, buf: &mut [u8], f: F) -> Option<usize> {
            let (t, buf) = buf.split_first_mut()?;
            *t = ty;
            f(buf).map(|i| i + 1)
        }
        match self {
            Self::Disconnect(o) => f(Self::DISCONNECT, buf, |buf| o.serialize(buf)),
            Self::Ignore(o) => f(Self::IGNORE, buf, |buf| o.serialize(buf)),
            Self::Unimplemented(o) => f(Self::UNIMPLEMENTED, buf, |buf| o.serialize(buf)),
            Self::Debug(o) => f(Self::DEBUG, buf, |buf| o.serialize(buf)),
            Self::ServiceRequest(o) => f(Self::SERVICE_REQUEST, buf, |buf| o.serialize(buf)),
            Self::ServiceAccept(o) => f(Self::SERVICE_ACCEPT, buf, |buf| o.serialize(buf)),
            Self::KeyExchangeInit(o) => f(Self::KEXINIT, buf, |buf| o.serialize(buf)),
            Self::NewKeys(o) => f(Self::NEWKEYS, buf, |buf| o.serialize(buf)),
            Self::KeyExchangeEcdhInit(o) => f(Self::KEX_ECDH_INIT, buf, |buf| o.serialize(buf)),
            Self::KeyExchangeEcdhReply(o) => f(Self::KEX_ECDH_REPLY, buf, |buf| o.serialize(buf)),
            Self::UserAuth(o) => o.serialize(buf),
            Self::Channel(o) => o.serialize(buf),
        }
        .map(|i| buf.split_at_mut(i))
    }
}

#[derive(Debug)]
pub enum MessageParseError {
    NoMessageType,
    UnknownMessageType(u8),
    Disconnect(DisconnectParseError),
    Ignore(IgnoreParseError),
    Unimplemented(UnimplementedParseError),
    Debug(DebugParseError),
    KeyExchangeInit(KeyExchangeInitParseError),
    NewKeys(NewKeysParseError),
    KeyExchangeEcdhInit(KeyExchangeEcdhInitParseError),
    KeyExchangeEcdhReply(KeyExchangeEcdhReplyParseError),
    ServiceRequest(ParseServiceRequestError),
    ServiceAccept(ParseServiceAcceptError),
    UserAuth(userauth::ParseError),
    Channel(channel::ParseError),
}

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
    fn parse(data: &'a [u8]) -> Result<Self, DisconnectParseError> {
        let reason = data.get(..4).ok_or(DisconnectParseError::BadLength)?;
        let description = parse_string(&data[4..]).ok_or(DisconnectParseError::BadLength)?;
        let data = &data[4 + 4 + description.len()..];
        let language = parse_string(data).ok_or(DisconnectParseError::BadLength)?;
        if data.len() != 4 + language.len() {
            Err(DisconnectParseError::BadLength)
        } else {
            Ok(Self {
                reason: u32::from_be_bytes(reason.try_into().unwrap()),
                description,
                language,
            })
        }
    }

    fn serialize(&self, buf: &mut [u8]) -> Option<usize> {
        let (a, buf) = make_uint32(buf, self.reason)?;
        let (b, buf) = make_string2(buf, self.description)?;
        let (c, _) = make_string2(buf, self.language)?;
        Some(a + b + c)
    }
}

#[derive(Debug)]
pub enum DisconnectParseError {
    BadLength,
}

pub struct Ignore<'a> {
    pub data: &'a [u8],
}

impl<'a> Ignore<'a> {
    fn parse(data: &'a [u8]) -> Result<Self, IgnoreParseError> {
        let (data, d) = parse_string3(data).ok_or(IgnoreParseError::Truncated)?;
        d.is_empty()
            .then(|| Self { data })
            .ok_or(IgnoreParseError::Unread)
    }

    fn serialize(&self, buf: &mut [u8]) -> Option<usize> {
        let (a, _) = make_string2(buf, self.data)?;
        Some(a)
    }
}

#[derive(Debug)]
pub enum IgnoreParseError {
    Truncated,
    Unread,
}

pub struct Unimplemented {
    pub sequence_number: u32,
}

impl Unimplemented {
    fn parse(data: &[u8]) -> Result<Self, UnimplementedParseError> {
        let (sequence_number, data) =
            parse_uint32(data).ok_or(UnimplementedParseError::Truncated)?;
        data.is_empty()
            .then(|| Self { sequence_number })
            .ok_or(UnimplementedParseError::Unread)
    }

    fn serialize(&self, buf: &mut [u8]) -> Option<usize> {
        let (a, _) = make_uint32(buf, self.sequence_number)?;
        Some(a)
    }
}

#[derive(Debug)]
pub enum UnimplementedParseError {
    Truncated,
    Unread,
}

pub struct Debug<'a> {
    pub always_display: bool,
    pub message: &'a str,
    pub language: &'a [u8],
}

impl<'a> Debug<'a> {
    fn parse(data: &'a [u8]) -> Result<Self, DebugParseError> {
        let (always_display, data) = parse_bool(data).ok_or(DebugParseError::Truncated)?;
        let (message, data) = parse_string3(data).ok_or(DebugParseError::Truncated)?;
        let (language, data) = parse_string3(data).ok_or(DebugParseError::Truncated)?;
        let message = core::str::from_utf8(message).map_err(|_| DebugParseError::InvalidUtf8)?;
        data.is_empty()
            .then(|| Self {
                always_display,
                message,
                language,
            })
            .ok_or(DebugParseError::Unread)
    }

    fn serialize(&self, buf: &mut [u8]) -> Option<usize> {
        let (a, buf) = make_bool(buf, self.always_display)?;
        let (b, buf) = make_string2(buf, self.message.as_ref())?;
        let (c, _) = make_string2(buf, self.language)?;
        Some(a + b + c)
    }
}

#[derive(Debug)]
pub enum DebugParseError {
    Truncated,
    Unread,
    InvalidUtf8,
}
