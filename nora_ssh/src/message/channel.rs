//! [RFC 4254]: https://datatracker.ietf.org/doc/html/rfc4254

use crate::data::{make_string_len, parse_string};

pub enum Channel<'a> {
    Open(Open<'a>),
    OpenConfirmation(OpenConfirmation<'a>),
    Data(Data<'a>),
    Eof(Eof),
    Request(Request<'a>),
    Success(Success),
    Failure(Failure),
}

impl<'a> Channel<'a> {
    const OPEN: u8 = 90;
    const OPEN_CONFIRMATION: u8 = 91;
    const OPEN_FAILURE: u8 = 92;
    const WINDOW_ADJUST: u8 = 93;
    const DATA: u8 = 94;
    const EXTENDED_DATA: u8 = 95;
    const EOF: u8 = 96;
    const CLOSE: u8 = 97;
    const REQUEST: u8 = 98;
    const SUCCESS: u8 = 99;
    const FAILURE: u8 = 100;

    pub(super) fn parse(ty: u8, data: &'a [u8]) -> Result<Self, ParseError> {
        match ty {
            Self::OPEN => Open::parse(data).map(Self::Open).map_err(ParseError::Open),
            Self::OPEN_CONFIRMATION => OpenConfirmation::parse(data)
                .map(Self::OpenConfirmation)
                .map_err(ParseError::OpenConfirmation),
            Self::DATA => Data::parse(data).map(Self::Data).map_err(ParseError::Data),
            Self::EOF => Eof::parse(data).map(Self::Eof).map_err(ParseError::Eof),
            Self::REQUEST => Request::parse(data)
                .map(Self::Request)
                .map_err(ParseError::Request),
            Self::SUCCESS => Success::parse(data)
                .map(Self::Success)
                .map_err(ParseError::Success),
            Self::FAILURE => Failure::parse(data)
                .map(Self::Failure)
                .map_err(ParseError::Failure),
            _ => Err(ParseError::UnknownMessageType(ty)),
        }
    }

    pub fn send<R, F>(&self, mut send: F) -> Result<(), R>
    where
        F: FnMut(&[u8]) -> Result<(), R>,
    {
        match self {
            Self::Open(_) => todo!(),
            Self::OpenConfirmation(oc) => {
                send(&[Self::OPEN_CONFIRMATION])?;
                oc.send(send)
            }
            Self::Data(d) => {
                send(&[Self::DATA])?;
                d.send(send)
            }
            Self::Eof(e) => {
                send(&[Self::EOF])?;
                e.send(send)
            }
            Self::Request(_) => todo!(),
            Self::Success(s) => {
                send(&[Self::SUCCESS])?;
                s.send(send)
            }
            Self::Failure(f) => {
                send(&[Self::FAILURE])?;
                f.send(send)
            }
        }
    }
}

#[derive(Debug)]
pub enum ParseError {
    UnknownMessageType(u8),
    Open(OpenParseError),
    OpenConfirmation(OpenConfirmationParseError),
    Data(DataParseError),
    Eof(EofParseError),
    Request(RequestParseError),
    Success(SuccessParseError),
    Failure(FailureParseError),
}

macro_rules! ch_as {
    ($v:ident -> $f:ident, $g:ident) => {
        impl Channel<'_> {
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

        impl From<$v> for Channel<'_> {
            fn from(v: $v) -> Self {
                Self::$v(v)
            }
        }
    };
    ('a $v:ident -> $f:ident, $g:ident) => {
        impl<'a> Channel<'a> {
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

        impl<'a> From<$v<'a>> for Channel<'a> {
            fn from(v: $v<'a>) -> Self {
                Self::$v(v)
            }
        }
    };
}

ch_as!('a Open -> as_open, into_open);
ch_as!('a OpenConfirmation -> as_open_confirmation, into_open_confirmation);
ch_as!('a Data -> as_data, into_data);
ch_as!('a Request -> as_request, into_request);
ch_as!(Success -> as_success, into_success);
ch_as!(Failure -> as_failure, into_failure);

pub struct Open<'a> {
    pub ty: &'a [u8],
    pub sender_channel: u32,
    pub window_size: u32,
    pub max_packet_size: u32,
}

impl<'a> Open<'a> {
    fn parse(data: &'a [u8]) -> Result<Self, OpenParseError> {
        let ty = parse_string(data).ok_or(OpenParseError::Truncated)?;
        let data = &data[4 + ty.len()..];
        if data.len() < 12 {
            Err(OpenParseError::Truncated)
        } else if data.len() > 12 {
            Err(OpenParseError::Unread)
        } else {
            let sender_channel = u32::from_be_bytes(data[..4].try_into().unwrap());
            let window_size = u32::from_be_bytes(data[4..8].try_into().unwrap());
            let max_packet_size = u32::from_be_bytes(data[8..].try_into().unwrap());
            Ok(Self {
                ty,
                sender_channel,
                window_size,
                max_packet_size,
            })
        }
    }
}

#[derive(Debug)]
pub enum OpenParseError {
    Truncated,
    Unread,
}

pub struct OpenConfirmation<'a> {
    pub recipient_channel: u32,
    pub sender_channel: u32,
    pub window_size: u32,
    pub max_packet_size: u32,
    pub stuff: &'a [u8],
}

impl<'a> OpenConfirmation<'a> {
    fn parse(data: &'a [u8]) -> Result<Self, OpenConfirmationParseError> {
        if data.len() < 16 {
            Err(OpenConfirmationParseError::Truncated)
        } else {
            let recipient_channel = u32::from_be_bytes(data[..4].try_into().unwrap());
            let sender_channel = u32::from_be_bytes(data[4..8].try_into().unwrap());
            let window_size = u32::from_be_bytes(data[8..12].try_into().unwrap());
            let max_packet_size = u32::from_be_bytes(data[12..16].try_into().unwrap());
            Ok(Self {
                recipient_channel,
                sender_channel,
                window_size,
                max_packet_size,
                stuff: &data[16..],
            })
        }
    }

    pub fn send<R, F>(&self, mut send: F) -> Result<(), R>
    where
        F: FnMut(&[u8]) -> Result<(), R>,
    {
        send(&self.recipient_channel.to_be_bytes())?;
        send(&self.sender_channel.to_be_bytes())?;
        send(&self.window_size.to_be_bytes())?;
        send(&self.max_packet_size.to_be_bytes())?;
        send(&self.stuff)
    }
}

#[derive(Debug)]
pub enum OpenConfirmationParseError {
    Truncated,
}

pub struct Data<'a> {
    pub recipient_channel: u32,
    pub data: &'a [u8],
}

impl<'a> Data<'a> {
    fn parse(data: &'a [u8]) -> Result<Self, DataParseError> {
        let recipient_channel = u32::from_be_bytes(
            data.get(..4)
                .ok_or(DataParseError::BadLength)?
                .try_into()
                .unwrap(),
        );
        let d = parse_string(&data[4..]).ok_or(DataParseError::BadLength)?;
        if data.len() != 4 + 4 + d.len() {
            Err(DataParseError::BadLength)
        } else {
            Ok(Self {
                recipient_channel,
                data: d,
            })
        }
    }

    pub fn send<R, F>(&self, mut send: F) -> Result<(), R>
    where
        F: FnMut(&[u8]) -> Result<(), R>,
    {
        send(&self.recipient_channel.to_be_bytes())?;
        send(&make_string_len(self.data))?;
        send(self.data)
    }
}

#[derive(Debug)]
pub enum DataParseError {
    BadLength,
}

pub struct Request<'a> {
    pub recipient_channel: u32,
    pub ty: &'a [u8],
    pub want_reply: bool,
    pub stuff: &'a [u8],
}

impl<'a> Request<'a> {
    fn parse(data: &'a [u8]) -> Result<Self, RequestParseError> {
        let recipient_channel = u32::from_be_bytes(
            data.get(..4)
                .ok_or(RequestParseError::Truncated)?
                .try_into()
                .unwrap(),
        );
        let ty = parse_string(&data[4..]).ok_or(RequestParseError::Truncated)?;
        let data = &data[4 + 4 + ty.len()..];
        let want_reply = *data.get(0).ok_or(RequestParseError::Truncated)? != 0;
        Ok(Self {
            recipient_channel,
            ty,
            want_reply,
            stuff: &data[1..],
        })
    }
}

#[derive(Debug)]
pub enum RequestParseError {
    Truncated,
}

macro_rules! chan_only {
    ($s:ident ? $e:ident) => {
        pub struct $s {
            pub recipient_channel: u32,
        }

        impl $s {
            fn parse(data: &[u8]) -> Result<Self, $e> {
                data.try_into()
                    .map(|n| Self {
                        recipient_channel: u32::from_be_bytes(n),
                    })
                    .map_err(|_| $e::BadLength)
            }

            pub fn send<R, F>(&self, mut send: F) -> Result<(), R>
            where
                F: FnMut(&[u8]) -> Result<(), R>,
            {
                send(&self.recipient_channel.to_be_bytes())
            }
        }

        #[derive(Debug)]
        pub enum $e {
            BadLength,
        }
    };
}

chan_only!(Eof ? EofParseError);
chan_only!(Success ? SuccessParseError);
chan_only!(Failure ? FailureParseError);
