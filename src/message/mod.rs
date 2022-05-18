mod key_exchange;

pub use key_exchange::{
    KeyExchangeEcdhInit, KeyExchangeEcdhInitParseError, KeyExchangeEcdhReply, KeyExchangeInit,
    KeyExchangeInitParseError, NewKeys, NewKeysParseError,
};

pub enum Message<'a> {
    KeyExchangeInit(KeyExchangeInit<'a>),
    KeyExchangeEcdhInit(KeyExchangeEcdhInit<'a>),
    NewKeys(NewKeys),
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

    pub fn parse(data: &'a [u8]) -> Result<Self, MessageParseError> {
        match *data.get(0).ok_or(MessageParseError::NoMessageType)? {
            Self::DISCONNECT => todo!(),
            Self::IGNORE => todo!(),
            Self::UNIMPLEMENTED => todo!(),
            Self::DEBUG => todo!(),
            Self::SERVICE_REQUEST => todo!(),
            Self::SERVICE_ACCEPT => todo!(),
            Self::KEXINIT => KeyExchangeInit::parse(&data[1..])
                .map(Self::KeyExchangeInit)
                .map_err(MessageParseError::KeyExchangeInitParseError),
            Self::NEWKEYS => NewKeys::parse(&data[1..])
                .map(Self::NewKeys)
                .map_err(MessageParseError::NewKeysParseError),
            Self::KEX_ECDH_INIT => KeyExchangeEcdhInit::parse(&data[1..])
                .map(Self::KeyExchangeEcdhInit)
                .map_err(MessageParseError::KeyExchangeEcdhInitParseError),
            Self::KEX_ECDH_REPLY => todo!(),
            ty => Err(MessageParseError::UnknownMessageType(ty)),
        }
    }

    pub fn send<R, F>(&self, mut send: F) -> Result<(), R>
    where
        F: FnMut(&[u8]) -> Result<(), R>,
    {
        match self {
            Self::KeyExchangeInit(_) => todo!(),
            Self::KeyExchangeEcdhInit(_) => todo!(),
            Self::NewKeys(NewKeys) => send(&[Self::NEWKEYS]),
        }
    }

    pub fn serialize<'s>(&self, buf: &'s mut [u8]) -> Result<&'s mut [u8], Full> {
        let mut i = 0;
        self.send(|d| {
            buf.get_mut(i..i + d.len())
                .map(|w| {
                    w.copy_from_slice(d);
                    i += d.len();
                })
                .ok_or(Full)
        })
        .map(|()| &mut buf[..i])
    }
}

#[derive(Debug)]
pub enum MessageParseError {
    NoMessageType,
    UnknownMessageType(u8),
    KeyExchangeInitParseError(KeyExchangeInitParseError),
    KeyExchangeEcdhInitParseError(KeyExchangeEcdhInitParseError),
    NewKeysParseError(NewKeysParseError),
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

msg!('a KeyExchangeInit -> as_kex_init, into_kex_init);
msg!('a KeyExchangeEcdhInit -> as_kex_ecdh_init, into_kex_ecdh_init);
msg!(NewKeys -> as_new_keys, into_new_keys);
