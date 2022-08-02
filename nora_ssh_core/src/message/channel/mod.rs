//! [RFC 4254]: https://datatracker.ietf.org/doc/html/rfc4254

pub mod session;

use crate::data::{
    make_bool, make_raw, make_string2, make_uint32, parse_string, parse_uint32,
};
use core::str;

pub enum Channel<'a> {
    Open(Open<'a>),
    OpenConfirmation(OpenConfirmation<'a>),
    OpenFailure(OpenFailure<'a>),
    WindowAdjust(WindowAdjust),
    Data(Data<'a>),
    ExtendedData(ExtendedData<'a>),
    Eof(Eof),
    Close(Close),
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
            Self::OPEN_FAILURE => OpenFailure::parse(data)
                .map(Self::OpenFailure)
                .map_err(ParseError::OpenFailure),
            Self::WINDOW_ADJUST => WindowAdjust::parse(data)
                .map(Self::WindowAdjust)
                .map_err(ParseError::WindowAdjust),
            Self::DATA => Data::parse(data).map(Self::Data).map_err(ParseError::Data),
            Self::EXTENDED_DATA => ExtendedData::parse(data)
                .map(Self::ExtendedData)
                .map_err(ParseError::ExtendedData),
            Self::EOF => Eof::parse(data).map(Self::Eof).map_err(ParseError::Eof),
            Self::CLOSE => Close::parse(data)
                .map(Self::Close)
                .map_err(ParseError::Close),
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

    pub fn serialize(&self, buf: &mut [u8]) -> Option<usize> {
        fn f<F: FnOnce(&mut [u8]) -> Option<usize>>(ty: u8, buf: &mut [u8], f: F) -> Option<usize> {
            let (t, buf) = buf.split_first_mut()?;
            *t = ty;
            f(buf).map(|i| i + 1)
        }
        match self {
            Self::Open(o) => f(Self::OPEN, buf, |b| o.serialize(b)),
            Self::OpenConfirmation(o) => f(Self::OPEN_CONFIRMATION, buf, |b| o.serialize(b)),
            Self::OpenFailure(o) => f(Self::OPEN_FAILURE, buf, |b| o.serialize(b)),
            Self::WindowAdjust(o) => f(Self::WINDOW_ADJUST, buf, |b| o.serialize(b)),
            Self::Data(o) => f(Self::DATA, buf, |b| o.serialize(b)),
            Self::ExtendedData(o) => f(Self::EXTENDED_DATA, buf, |b| o.serialize(b)),
            Self::Eof(o) => f(Self::EOF, buf, |b| o.serialize(b)),
            Self::Close(o) => f(Self::CLOSE, buf, |b| o.serialize(b)),
            Self::Request(o) => f(Self::REQUEST, buf, |b| o.serialize(b)),
            Self::Success(o) => f(Self::SUCCESS, buf, |b| o.serialize(b)),
            Self::Failure(o) => f(Self::FAILURE, buf, |b| o.serialize(b)),
        }
    }
}

#[derive(Debug)]
pub enum ParseError {
    UnknownMessageType(u8),
    Open(OpenParseError),
    OpenConfirmation(OpenConfirmationParseError),
    OpenFailure(OpenFailureParseError),
    WindowAdjust(WindowAdjustParseError),
    Data(DataParseError),
    ExtendedData(ExtendedDataParseError),
    Eof(EofParseError),
    Close(CloseParseError),
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
ch_as!(Close -> as_close, into_close);
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
        let (ty, data) = parse_string(data).ok_or(OpenParseError::Truncated)?;
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

    fn serialize(&self, buf: &mut [u8]) -> Option<usize> {
        let (a, buf) = make_string2(buf, self.ty)?;
        let (b, buf) = make_uint32(buf, self.sender_channel)?;
        let (c, buf) = make_uint32(buf, self.window_size)?;
        let (d, _) = make_uint32(buf, self.max_packet_size)?;
        Some(a + b + c + d)
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
    pub data: &'a [u8],
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
                data: &data[16..],
            })
        }
    }

    fn serialize(&self, buf: &mut [u8]) -> Option<usize> {
        let (a, buf) = make_uint32(buf, self.recipient_channel)?;
        let (b, buf) = make_uint32(buf, self.sender_channel)?;
        let (c, buf) = make_uint32(buf, self.window_size)?;
        let (d, buf) = make_uint32(buf, self.max_packet_size)?;
        let (e, _) = make_raw(buf, self.data)?;
        Some(a + b + c + d + e)
    }
}

#[derive(Debug)]
pub enum OpenConfirmationParseError {
    Truncated,
}

pub struct OpenFailure<'a> {
    pub recipient_channel: u32,
    pub reason: OpenFailureReason,
    pub description: &'a str,
    pub language: &'a [u8],
}

impl<'a> OpenFailure<'a> {
    fn parse(data: &'a [u8]) -> Result<Self, OpenFailureParseError> {
        let (recipient_channel, data) =
            parse_uint32(data).ok_or(OpenFailureParseError::Truncated)?;
        let (reason, data) = parse_uint32(data).ok_or(OpenFailureParseError::Truncated)?;
        let (description, data) = parse_string(data).ok_or(OpenFailureParseError::Truncated)?;
        let (language, data) = parse_string(data).ok_or(OpenFailureParseError::Truncated)?;
        data.is_empty()
            .then(|| ())
            .ok_or(OpenFailureParseError::Unread)?;
        Ok(Self {
            recipient_channel,
            reason: match reason {
                1 => OpenFailureReason::AdminstrativelyProhibited,
                2 => OpenFailureReason::ConnectFailed,
                3 => OpenFailureReason::UnknownChannelType,
                4 => OpenFailureReason::ResourceShortage,
                r => OpenFailureReason::Other(r),
            },
            description: str::from_utf8(description)
                .map_err(|_| OpenFailureParseError::InvalidUtf8)?,
            language,
        })
    }

    fn serialize(&self, buf: &mut [u8]) -> Option<usize> {
        let (a, buf) = make_uint32(buf, self.recipient_channel)?;
        let (b, buf) = make_uint32(
            buf,
            match self.reason {
                OpenFailureReason::AdminstrativelyProhibited => 1,
                OpenFailureReason::ConnectFailed => 2,
                OpenFailureReason::UnknownChannelType => 3,
                OpenFailureReason::ResourceShortage => 4,
                OpenFailureReason::Other(r) => r,
            },
        )?;
        let (c, buf) = make_string2(buf, self.description.as_ref())?;
        let (d, _) = make_string2(buf, self.language)?;
        Some(a + b + c + d)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum OpenFailureReason {
    AdminstrativelyProhibited,
    ConnectFailed,
    UnknownChannelType,
    ResourceShortage,
    Other(u32),
}

#[derive(Debug)]
pub enum OpenFailureParseError {
    Truncated,
    Unread,
    InvalidUtf8,
}

pub struct WindowAdjust {
    pub recipient_channel: u32,
    pub add_bytes: u32,
}

impl WindowAdjust {
    fn parse(data: &[u8]) -> Result<Self, WindowAdjustParseError> {
        let (recipient_channel, data) =
            parse_uint32(data).ok_or(WindowAdjustParseError::Truncated)?;
        let (add_bytes, data) = parse_uint32(data).ok_or(WindowAdjustParseError::Truncated)?;
        data.is_empty()
            .then(|| Self {
                recipient_channel,
                add_bytes,
            })
            .ok_or(WindowAdjustParseError::Unread)
    }

    fn serialize(&self, buf: &mut [u8]) -> Option<usize> {
        let (a, buf) = make_uint32(buf, self.recipient_channel)?;
        let (b, _) = make_uint32(buf, self.add_bytes)?;
        Some(a + b)
    }
}

#[derive(Debug)]
pub enum WindowAdjustParseError {
    Truncated,
    Unread,
}

pub struct Data<'a> {
    pub recipient_channel: u32,
    pub data: &'a [u8],
}

impl<'a> Data<'a> {
    fn parse(data: &'a [u8]) -> Result<Self, DataParseError> {
        let (recipient_channel, data) = parse_uint32(data).ok_or(DataParseError::Truncated)?;
        let (data, d) = parse_string(data).ok_or(DataParseError::Truncated)?;
        d.is_empty()
            .then(|| Self {
                recipient_channel,
                data,
            })
            .ok_or(DataParseError::Unread)
    }

    fn serialize(&self, buf: &mut [u8]) -> Option<usize> {
        let (a, buf) = make_uint32(buf, self.recipient_channel)?;
        let (b, _) = make_string2(buf, self.data)?;
        Some(a + b)
    }
}

#[derive(Debug)]
pub enum DataParseError {
    Truncated,
    Unread,
}

pub struct ExtendedData<'a> {
    pub recipient_channel: u32,
    pub ty: u32,
    pub data: &'a [u8],
}

impl<'a> ExtendedData<'a> {
    fn parse(data: &'a [u8]) -> Result<Self, ExtendedDataParseError> {
        let (recipient_channel, data) =
            parse_uint32(data).ok_or(ExtendedDataParseError::Truncated)?;
        let (ty, data) = parse_uint32(data).ok_or(ExtendedDataParseError::Truncated)?;
        let (data, d) = parse_string(data).ok_or(ExtendedDataParseError::Truncated)?;
        d.is_empty()
            .then(|| Self {
                recipient_channel,
                ty,
                data,
            })
            .ok_or(ExtendedDataParseError::Unread)
    }

    fn serialize(&self, buf: &mut [u8]) -> Option<usize> {
        let (a, buf) = make_uint32(buf, self.recipient_channel)?;
        let (b, buf) = make_uint32(buf, self.ty)?;
        let (c, _) = make_string2(buf, self.data)?;
        Some(a + b + c)
    }
}

#[derive(Debug)]
pub enum ExtendedDataParseError {
    Truncated,
    Unread,
}

pub struct Request<'a> {
    pub recipient_channel: u32,
    pub ty: &'a [u8],
    pub want_reply: bool,
    pub data: &'a [u8],
}

impl<'a> Request<'a> {
    fn parse(data: &'a [u8]) -> Result<Self, RequestParseError> {
        let recipient_channel = u32::from_be_bytes(
            data.get(..4)
                .ok_or(RequestParseError::Truncated)?
                .try_into()
                .unwrap(),
        );
        let (ty, data) = parse_string(&data[4..]).ok_or(RequestParseError::Truncated)?;
        let want_reply = *data.get(0).ok_or(RequestParseError::Truncated)? != 0;
        Ok(Self {
            recipient_channel,
            ty,
            want_reply,
            data: &data[1..],
        })
    }

    fn serialize(&self, buf: &mut [u8]) -> Option<usize> {
        let (a, buf) = make_uint32(buf, self.recipient_channel)?;
        let (b, buf) = make_string2(buf, self.ty)?;
        let (c, buf) = make_bool(buf, self.want_reply)?;
        let (d, _) = make_raw(buf, self.data)?;
        Some(a + b + c + d)
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

            fn serialize(&self, buf: &mut [u8]) -> Option<usize> {
                let (a, _) = make_uint32(buf, self.recipient_channel)?;
                Some(a)
            }
        }

        #[derive(Debug)]
        pub enum $e {
            BadLength,
        }
    };
}

chan_only!(Eof ? EofParseError);
chan_only!(Close ? CloseParseError);
chan_only!(Success ? SuccessParseError);
chan_only!(Failure ? FailureParseError);

#[cfg(test)]
mod test {
    use super::{super::Message, *};

    macro_rules! sds {
        ($name:ident => $v:ident = $val:expr) => {
            #[test]
            fn $name() {
                let mut a @ mut b = [0; 2048];
                let a = Message::Channel(Channel::$v($val))
                    .serialize(&mut a)
                    .unwrap()
                    .0;
                let b = Message::parse(a).unwrap().serialize(&mut b).unwrap().0;
                assert_eq!(a, b);
            }
        };
    }

    sds!(serialize_deserialize_serialize_open => Open = Open {
        sender_channel: 29302,
        max_packet_size: 898439,
        window_size: 2930403,
        ty: b"reogrjeo",
    });

    sds!(serialize_deserialize_serialize_open_confirmation => OpenConfirmation = OpenConfirmation {
        recipient_channel: 23289329,
        sender_channel: 29302,
        max_packet_size: 898439,
        window_size: 2930403,
        data: b"erjrejogrjeogjorejo",
    });

    sds!(serialize_deserialize_serialize_open_failure => OpenFailure = OpenFailure {
        recipient_channel: 23289329,
        description: "okreoirgjo",
        language: b"reogkgorek",
        reason: OpenFailureReason::ResourceShortage,
    });

    sds!(serialize_deserialize_serialize_window_adjust => WindowAdjust = WindowAdjust {
        recipient_channel: 2940402,
        add_bytes: 28398492,
    });

    sds!(serialize_deserialize_serialize_data => Data = Data {
        recipient_channel: 2940402,
        data: b"fezpofkorzjgiejgjrejgoiregjrejoir",
    });

    sds!(serialize_deserialize_serialize_extended_data => ExtendedData = ExtendedData {
        recipient_channel: 2940402,
        ty: 2949430,
        data: b"fezpofkorzjgiejgjrejgoiregjrejoir",
    });

    sds!(serialize_deserialize_serialize_eof => Eof = Eof {
        recipient_channel: 2940402,
    });

    sds!(serialize_deserialize_serialize_close => Close = Close {
        recipient_channel: 2940402,
    });

    sds!(serialize_deserialize_serialize_request => Request = Request {
        recipient_channel: 2940402,
        want_reply: true,
        ty: b"orgkorekogire",
        data: b"KERKEKokofkforkeoi",
    });

    sds!(serialize_deserialize_serialize_success => Success = Success {
        recipient_channel: 2940402,
    });

    sds!(serialize_deserialize_serialize_failure => Failure = Failure {
        recipient_channel: 2940402,
    });
}
