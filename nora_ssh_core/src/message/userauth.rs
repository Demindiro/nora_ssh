//! Implementation based on [RFC 4252].
//!
//! [RFC 4252]: https://datatracker.ietf.org/doc/html/rfc4252

use crate::{
    data::{make_bool, make_raw, make_string2, parse_string, AsciiStr, InvalidNameList, NameList},
    identifier::Identifier,
};
use core::str;

pub enum UserAuth<'a> {
    Request(Request<'a>),
    Failure(Failure<'a>),
    Success(Success),
    Banner(Banner<'a>),
    PublicKeyOk(PublicKeyOk<'a>),
}

impl<'a> UserAuth<'a> {
    const REQUEST: u8 = 50;
    const FAILURE: u8 = 51;
    const SUCCESS: u8 = 52;
    const BANNER: u8 = 53;
    const PK_OK: u8 = 60;

    pub(super) fn parse(ty: u8, data: &'a [u8]) -> Result<Self, ParseError> {
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
            Self::PK_OK => PublicKeyOk::parse(data)
                .map(UserAuth::PublicKeyOk)
                .map_err(ParseError::PublicKeyOk),
            ty => Err(ParseError::UnknownMessageType(ty)),
        }
    }

    pub(super) fn serialize(&self, buf: &mut [u8]) -> Option<usize> {
        let (t, buf) = buf.split_first_mut()?;
        match self {
            Self::Request(req) => {
                *t = Self::REQUEST;
                req.serialize(buf)
            }
            Self::Failure(f) => {
                *t = Self::FAILURE;
                f.serialize(buf)
            }
            Self::Success(s) => {
                *t = Self::SUCCESS;
                s.serialize(buf)
            }
            Self::Banner(b) => {
                *t = Self::BANNER;
                b.serialize(buf)
            }
            Self::PublicKeyOk(pk) => {
                *t = Self::PK_OK;
                pk.serialize(buf)
            }
        }
        .map(|i| i + 1)
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
ua_as!('a PublicKeyOk -> as_public_key_ok, into_public_key_ok);

#[derive(Debug)]
pub enum ParseError {
    UnknownMessageType(u8),
    Request(RequestParseError),
    Failure(FailureParseError),
    Success(SuccessParseError),
    Banner(BannerParseError),
    PublicKeyOk(PublicKeyOkParseError),
}

pub struct Request<'a> {
    pub user: &'a [u8],
    pub service: &'a [u8],
    pub method: Method<'a>,
}

impl<'a> Request<'a> {
    fn parse(data: &'a [u8]) -> Result<Self, RequestParseError> {
        let parse = |data| parse_string(data).ok_or(RequestParseError::Truncated);
        let empty = |data: &[_]| data.is_empty().then(|| ()).ok_or(RequestParseError::Unread);
        let (user, data) = parse(data)?;
        let (service, data) = parse(data)?;
        let (method, data) = parse(data)?;
        let method = match method {
            b"none" => empty(data).map(|()| Method::None)?,
            b"publickey" => {
                let (sign, data) = data.split_first().ok_or(RequestParseError::Truncated)?;
                if *sign == 0 {
                    let (algorithm, data) = parse(data)?;
                    let (blob, data) = parse(data)?;
                    empty(data)?;
                    Method::PublicKeyBlob { algorithm, blob }
                } else {
                    let (algorithm, data) = parse(data)?;
                    let (key, data) = parse(data)?;
                    let (signature, data) = parse(data)?;
                    empty(data)?;
                    Method::PublicKeySigned {
                        algorithm,
                        key,
                        signature,
                    }
                }
            }
            b"password" => {
                let (renew, data) = data.split_first().ok_or(RequestParseError::Truncated)?;
                if *renew == 0 {
                    let (password, data) = parse(data)?;
                    empty(data)?;
                    Method::Password { password }
                } else {
                    let (old_password, data) = parse(data)?;
                    let (new_password, data) = parse(data)?;
                    empty(data)?;
                    Method::PasswordRenew {
                        old_password,
                        new_password,
                    }
                }
            }
            b"hostbased" => {
                let (algorithm, data) = parse(data)?;
                let (key_and_certificates, data) = parse(data)?;
                let (host_name, data) = parse(data)?;
                let (user_name, data) = parse(data)?;
                let (signature, data) = parse(data)?;
                empty(data)?;
                Method::HostBased {
                    algorithm,
                    key_and_certificates,
                    host_name: AsciiStr::try_from(host_name)
                        .map_err(|_| RequestParseError::NotAscii)?,
                    user_name: str::from_utf8(user_name).map_err(|_| RequestParseError::NotUtf8)?,
                    signature,
                }
            }
            _ => Method::Other { method, data },
        };
        Ok(Self {
            user,
            service,
            method,
        })
    }

    fn serialize(&self, buf: &mut [u8]) -> Option<usize> {
        let (a, buf) = make_string2(buf, self.user)?;
        let (b, buf) = make_string2(buf, self.service)?;
        let c = match self.method {
            Method::None => make_string2(buf, b"none")?.0,
            Method::PublicKeyBlob { algorithm, blob } => {
                let (d, buf) = make_string2(buf, b"publickey")?;
                let (e, buf) = make_bool(buf, false)?;
                let (f, buf) = make_string2(buf, algorithm)?;
                let (g, _) = make_string2(buf, blob)?;
                d + e + f + g
            }
            Method::PublicKeySigned {
                algorithm,
                key,
                signature,
            } => {
                let (d, buf) = make_string2(buf, b"publickey")?;
                let (e, buf) = make_bool(buf, true)?;
                let (f, buf) = make_string2(buf, algorithm)?;
                let (g, buf) = make_string2(buf, key)?;
                let (h, _) = make_string2(buf, signature)?;
                d + e + f + g + h
            }
            Method::Password { password } => {
                let (d, buf) = make_string2(buf, b"password")?;
                let (e, buf) = make_bool(buf, false)?;
                let (f, _) = make_string2(buf, password)?;
                d + e + f
            }
            Method::PasswordRenew {
                old_password,
                new_password,
            } => {
                let (d, buf) = make_string2(buf, b"password")?;
                let (e, buf) = make_bool(buf, true)?;
                let (f, buf) = make_string2(buf, old_password)?;
                let (g, _) = make_string2(buf, new_password)?;
                d + e + f + g
            }
            Method::HostBased {
                algorithm,
                key_and_certificates,
                host_name,
                user_name,
                signature,
            } => {
                let (d, buf) = make_string2(buf, b"hostbased")?;
                let (e, buf) = make_string2(buf, algorithm)?;
                let (f, buf) = make_string2(buf, key_and_certificates)?;
                let (g, buf) = make_string2(buf, host_name.into())?;
                let (h, buf) = make_string2(buf, user_name.as_ref())?;
                let (i, _) = make_string2(buf, signature)?;
                d + e + f + g + h + i
            }
            Method::Other { method, data } => {
                let (d, buf) = make_string2(buf, method)?;
                let (e, _) = make_raw(buf, data)?;
                d + e
            }
        };
        Some(a + b + c)
    }
}

#[derive(Clone, Copy, Debug)]
pub enum Method<'a> {
    None,
    PublicKeyBlob {
        algorithm: &'a [u8],
        blob: &'a [u8],
    },
    PublicKeySigned {
        algorithm: &'a [u8],
        key: &'a [u8],
        signature: &'a [u8],
    },
    Password {
        password: &'a [u8],
    },
    PasswordRenew {
        old_password: &'a [u8],
        new_password: &'a [u8],
    },
    HostBased {
        algorithm: &'a [u8],
        key_and_certificates: &'a [u8],
        host_name: AsciiStr<'a>,
        user_name: &'a str,
        signature: &'a [u8],
    },
    Other {
        method: &'a [u8],
        data: &'a [u8],
    },
}

#[derive(Debug)]
pub enum RequestParseError {
    Truncated,
    Unread,
    NotAscii,
    NotUtf8,
}

pub struct Failure<'a> {
    pub alternative_methods: NameList<'a>,
    pub partial_success: bool,
}

impl<'a> Failure<'a> {
    fn parse(data: &'a [u8]) -> Result<Self, FailureParseError> {
        let (alternative_methods, data) = parse_string(data).ok_or(FailureParseError::Truncated)?;
        match data {
            &[] => Err(FailureParseError::Truncated),
            &[partial_success] => Ok(Self {
                alternative_methods: NameList::try_from(alternative_methods)
                    .map_err(FailureParseError::InvalidNameList)?,
                partial_success: partial_success != 0,
            }),
            &[..] => Err(FailureParseError::Unread),
        }
    }

    fn serialize(&self, buf: &mut [u8]) -> Option<usize> {
        let (a, buf) = make_string2(buf, self.alternative_methods.into())?;
        let (b, _) = make_bool(buf, self.partial_success)?;
        Some(a + b)
    }
}

#[derive(Debug)]
pub enum FailureParseError {
    Truncated,
    Unread,
    InvalidNameList(InvalidNameList),
}

pub struct Success;

impl Success {
    fn parse(data: &[u8]) -> Result<Self, SuccessParseError> {
        data.is_empty()
            .then(|| Self)
            .ok_or(SuccessParseError::Unread)
    }

    fn serialize(&self, _buf: &mut [u8]) -> Option<usize> {
        Some(0)
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
        let (message, data) = parse_string(data).ok_or(BannerParseError::Truncated)?;
        let (language, data) = parse_string(data).ok_or(BannerParseError::Truncated)?;
        data.is_empty()
            .then(|| Self { message, language })
            .ok_or(BannerParseError::Unread)
    }

    fn serialize(&self, buf: &mut [u8]) -> Option<usize> {
        let (a, buf) = make_string2(buf, self.message)?;
        let (b, _) = make_string2(buf, self.language)?;
        Some(a + b)
    }
}

#[derive(Debug)]
pub enum BannerParseError {
    Truncated,
    Unread,
}

pub struct PublicKeyOk<'a> {
    pub algorithm: &'a [u8],
    pub blob: &'a [u8],
}

impl<'a> PublicKeyOk<'a> {
    fn parse(data: &'a [u8]) -> Result<Self, PublicKeyOkParseError> {
        let (algorithm, data) = parse_string(data).ok_or(PublicKeyOkParseError::Truncated)?;
        let (blob, data) = parse_string(data).ok_or(PublicKeyOkParseError::Truncated)?;
        data.is_empty()
            .then(|| Self { algorithm, blob })
            .ok_or(PublicKeyOkParseError::Unread)
    }

    fn serialize(&self, buf: &mut [u8]) -> Option<usize> {
        let (a, buf) = make_string2(buf, self.algorithm)?;
        let (b, _) = make_string2(buf, self.blob)?;
        Some(a + b)
    }
}

#[derive(Debug)]
pub enum PublicKeyOkParseError {
    Truncated,
    Unread,
}

/// Format data for signing & verifying client keys.
///
/// Fails if the buffer is too small.
pub fn format_sign_data<'a>(
    buf: &'a mut [u8],
    session_identifier: &[u8],
    user: &[u8],
    service: &[u8],
    algorithm: &[u8],
    blob: &[u8],
) -> Option<&'a [u8]> {
    let (_, b) = make_string2(buf, session_identifier)?;
    let (_, b) = make_raw(b, &[UserAuth::REQUEST])?;
    let (_, b) = make_string2(b, user)?;
    let (_, b) = make_string2(b, service)?;
    let (_, b) = make_string2(b, b"publickey")?;
    let (_, b) = make_bool(b, true)?;
    let (_, b) = make_string2(b, algorithm)?;
    let (_, b) = make_string2(b, blob)?;
    let l = b.len();
    Some(&buf[..buf.len() - l])
}

#[cfg(test)]
mod test {
    use super::{super::Message, *};

    macro_rules! sds {
        ($name:ident => $v:ident = $val:expr) => {
            #[test]
            fn $name() {
                let mut a @ mut b = [0; 2048];
                let a = Message::UserAuth(UserAuth::$v($val))
                    .serialize(&mut a)
                    .unwrap()
                    .0;
                let b = Message::parse(a).unwrap().serialize(&mut b).unwrap().0;
                assert_eq!(a, b);
            }
        };
    }

    sds!(serialize_deserialize_serialize_request_none => Request = Request {
        user: b"duck",
        service: b"seeds",
        method: Method::None,
    });

    sds!(serialize_deserialize_serialize_request_public_key_blob => Request = Request {
        user: b"duck",
        service: b"seeds",
        method: Method::PublicKeyBlob {
            algorithm: b"eat",
            blob: b"nomnomnomnomnomnomnom\xffnomnomquacknomnom",
        },
    });

    sds!(serialize_deserialize_serialize_request_public_key_signed => Request = Request {
        user: b"duck",
        service: b"seeds",
        method: Method::PublicKeySigned {
            algorithm: b"eat",
            key: b"$",
            signature: b"x",
        },
    });

    sds!(serialize_deserialize_serialize_request_password => Request = Request {
        user: b"duck",
        service: b"seeds",
        method: Method::Password {
            password: b"1234",
        },
    });

    sds!(serialize_deserialize_serialize_request_password_renew => Request = Request {
        user: b"duck",
        service: b"seeds",
        method: Method::PasswordRenew {
            old_password: b"1234",
            new_password: b"4321",
        },
    });

    sds!(serialize_deserialize_serialize_request_host_based => Request = Request {
        user: b"duck",
        service: b"seeds",
        method: Method::HostBased {
            algorithm: b"quack",
            key_and_certificates: b"",
            host_name: AsciiStr::try_from(b"France").unwrap(),
            user_name: "Napoleon Bonaparte",
            signature: b"x",
        },
    });

    sds!(serialize_deserialize_serialize_failure => Failure = Failure {
        alternative_methods: NameList::try_from(b"foo,bar,baz").unwrap(),
        partial_success: false,
    });

    sds!(serialize_deserialize_serialize_success => Success = Success);

    sds!(serialize_deserialize_serialize_banner => Banner = Banner {
        message: b"gonigeojirgeojiegrojirgeojirgeojiergoji",
        language: b"animal",
    });

    sds!(serialize_deserialize_serialize_public_key_ok => PublicKeyOk = PublicKeyOk {
        algorithm: b"rgeojrgeojirgeorije",
        blob: b"oieojirgergeoji",
    });
}
