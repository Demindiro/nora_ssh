use crate::data::{parse_string, parse_string2};

pub enum UserAuth<'a> {
    Request(Request<'a>),
    Failure(Failure<'a>),
    Success(Success),
    Banner(Banner<'a>),
}

impl<'a> UserAuth<'a> {
    const REQUEST: u8 = 50;
    const FAILURE: u8 = 51;
    const SUCCESS: u8 = 52;
    const BANNER: u8 = 53;

    pub fn parse(ty: u8, data: &'a [u8]) -> Result<Self, ParseError> {
        match ty {
            Self::REQUEST => Request::parse(data)
                .map(UserAuth::Request)
                .map_err(ParseError::Request),
            Self::FAILURE => Failure::parse(data)
                .map(UserAuth::Failure)
                .map_err(ParseError::Failure),
            Self::SUCCESS => Success::parse(data)
                .map(UserAuth::Success)
                .map_err(ParseError::Success),
            Self::BANNER => Banner::parse(data)
                .map(UserAuth::Banner)
                .map_err(ParseError::Banner),
            ty => Err(ParseError::UnknownMessageType(ty)),
        }
    }

    pub fn send<R, F>(&self, mut send: F) -> Result<(), R>
    where
        F: FnMut(&[u8]) -> Result<(), R>,
    {
        match self {
            Self::Request(_) => todo!(),
            Self::Failure(_) => todo!(),
            Self::Success(Success) => send(&[Self::SUCCESS]),
            Self::Banner(_) => todo!(),
        }
    }
}

macro_rules! ua_as {
    ($v:ident -> $f:ident, $g:ident) => {
        impl UserAuth<'_> {
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

        impl From<$v> for UserAuth<'_> {
            fn from(v: $v) -> Self {
                Self::$v(v)
            }
        }
    };
    ('a $v:ident -> $f:ident, $g:ident) => {
        impl<'a> UserAuth<'a> {
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

        impl<'a> From<$v<'a>> for UserAuth<'a> {
            fn from(v: $v<'a>) -> Self {
                Self::$v(v)
            }
        }
    };
}

ua_as!('a Request -> as_request, into_request);
ua_as!('a Failure -> as_failure, into_failure);
ua_as!(Success -> as_success, into_success);
ua_as!('a Banner -> as_banner, into_banner);

#[derive(Debug)]
pub enum ParseError {
    UnknownMessageType(u8),
    Request(RequestParseError),
    Failure(FailureParseError),
    Success(SuccessParseError),
    Banner(BannerParseError),
}

pub struct Request<'a> {
    pub user: &'a [u8],
    pub service: &'a [u8],
    pub method: &'a [u8],
    stuff: &'a [u8],
}

impl<'a> Request<'a> {
    fn parse(data: &'a [u8]) -> Result<Self, RequestParseError> {
        let user = parse_string(data).ok_or(RequestParseError::Truncated)?;
        let data = &data[4 + user.len()..];
        let service = parse_string(data).ok_or(RequestParseError::Truncated)?;
        let data = &data[4 + service.len()..];
        let method = parse_string(data).ok_or(RequestParseError::Truncated)?;
        let data = &data[4 + method.len()..];
        Ok(Self {
            user,
            service,
            method,
            stuff: data,
        })
    }
}

#[derive(Debug)]
pub enum RequestParseError {
    Truncated,
    Unread,
}

pub struct Failure<'a> {
    alternative_methods: &'a [u8],
    partial_success: bool,
}

impl<'a> Failure<'a> {
    fn parse(data: &'a [u8]) -> Result<Self, FailureParseError> {
        let (message, i) = parse_string2(data).ok_or(BannerParseError::Truncated)?;
    }
}

#[derive(Debug)]
pub enum FailureParseError {
    Truncated,
    Unread,
}

pub struct Success;

impl Success {
    fn parse(data: &[u8]) -> Result<Self, SuccessParseError> {
        data.is_empty().then(|| Self).ok_or(SuccessParseError::Unread)
    }
}

#[derive(Debug)]
pub enum SuccessParseError {
    Unread,
}

pub struct Banner<'a> {
    pub message: &'a [u8],
    pub language: &'a [u8],
}

impl<'a> Banner<'a> {
    fn parse(data: &'a [u8]) -> Result<Self, BannerParseError> {
        let (message, i) = parse_string2(data).ok_or(BannerParseError::Truncated)?;
        let (language, i) = parse_string2(&data[i..]).ok_or(BannerParseError::Truncated)?;
        (i == data.len()).then(|| Self { message, language }).ok_or(BannerParseError::Unread)
    }
}

#[derive(Debug)]
pub enum BannerParseError {
    Truncated,
    Unread,
}
