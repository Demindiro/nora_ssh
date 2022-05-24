//! Based on [RFC 4254 Section 5].
//!
//! [RFC 4254 Section 5]: https://datatracker.ietf.org/doc/html/rfc4254#section-5

use crate::data::{parse_bool, parse_string3, parse_uint32};
use core::str;

pub enum SessionRequest<'a> {
    Pty {
        terminal: &'a [u8],
        char_width: u32,
        char_height: u32,
        pixel_width: u32,
        pixel_height: u32,
        modes: &'a [u8],
    },
    X11 {
        single_connection: bool,
        auth_protocol: &'a [u8],
        auth_cookie: &'a [u8],
        screen: u32,
    },
    Env {
        name: &'a [u8],
        value: &'a [u8],
    },
    Shell,
    Exec {
        command: &'a [u8],
    },
    Subsystem {
        name: &'a [u8],
    },
    WindowChange {
        char_width: u32,
        char_height: u32,
        pixel_width: u32,
        pixel_height: u32,
    },
    XonXoff {
        on: bool,
    },
    Signal {
        signal: Signal<'a>,
    },
    ExitStatus {
        status: u32,
    },
    ExitSignal {
        signal: Signal<'a>,
        core_dumped: bool,
        message: &'a str,
        language: &'a [u8],
    },
}

impl<'a> SessionRequest<'a> {
    pub fn parse(ty: &'a [u8], data: &'a [u8]) -> Result<Self, ParseError> {
        let parse_str = |data| parse_string3(data).ok_or(ParseError::Truncated);
        let parse_u32 = |data| parse_uint32(data).ok_or(ParseError::Truncated);
        let parse_bool = |data| parse_bool(data).ok_or(ParseError::Truncated);
        let empty = |data: &[_]| data.is_empty().then(|| ()).ok_or(ParseError::Unread);
        match ty {
            b"pty-req" => {
                let (terminal, data) = parse_str(data)?;
                let (char_width, data) = parse_u32(data)?;
                let (char_height, data) = parse_u32(data)?;
                let (pixel_width, data) = parse_u32(data)?;
                let (pixel_height, data) = parse_u32(data)?;
                let (modes, data) = parse_str(data)?;
                empty(data).map(|()| Self::Pty {
                    terminal,
                    char_width,
                    char_height,
                    pixel_width,
                    pixel_height,
                    modes,
                })
            }
            b"x11-req" => {
                let (single_connection, data) = parse_bool(data)?;
                let (auth_protocol, data) = parse_str(data)?;
                let (auth_cookie, data) = parse_str(data)?;
                let (screen, data) = parse_u32(data)?;
                empty(data).map(|()| Self::X11 {
                    single_connection,
                    auth_protocol,
                    auth_cookie,
                    screen,
                })
            }
            b"env" => {
                let (name, data) = parse_str(data)?;
                let (value, data) = parse_str(data)?;
                empty(data).map(|()| Self::Env { name, value })
            }
            b"shell" => empty(data).map(|()| Self::Shell),
            b"exec" => {
                let (command, data) = parse_str(data)?;
                empty(data).map(|()| Self::Exec { command })
            }
            b"subsystem" => {
                let (name, data) = parse_str(data)?;
                empty(data).map(|()| Self::Subsystem { name })
            }
            b"window-change" => {
                let (char_width, data) = parse_u32(data)?;
                let (char_height, data) = parse_u32(data)?;
                let (pixel_width, data) = parse_u32(data)?;
                let (pixel_height, data) = parse_u32(data)?;
                empty(data).map(|()| Self::WindowChange {
                    char_width,
                    char_height,
                    pixel_width,
                    pixel_height,
                })
            }
            b"xon-xoff" => {
                let (on, data) = parse_bool(data)?;
                empty(data).map(|()| Self::XonXoff { on })
            }
            b"signal" => {
                let (signal, data) = parse_str(data)?;
                empty(data).map(|()| Self::Signal {
                    signal: signal.into(),
                })
            }
            b"exit-status" => {
                let (status, data) = parse_u32(data)?;
                empty(data).map(|()| Self::ExitStatus { status })
            }
            b"exit-signal" => {
                let (signal, data) = parse_str(data)?;
                let (core_dumped, data) = parse_bool(data)?;
                let (message, data) = parse_str(data)?;
                let (language, data) = parse_str(data)?;
                empty(data).and_then(|()| {
                    Ok(Self::ExitSignal {
                        signal: signal.into(),
                        core_dumped,
                        message: str::from_utf8(message).map_err(|_| ParseError::InvalidUtf8)?,
                        language,
                    })
                })
            }
            _ => Err(ParseError::Unknown),
        }
    }
}

#[derive(Debug)]
pub enum ParseError {
    Unknown,
    Truncated,
    Unread,
    InvalidUtf8,
}

pub enum Signal<'a> {
    Abort,
    Alarm,
    FloatingPointException,
    Hangup,
    Illegal,
    Interrupt,
    Kill,
    Pipe,
    Quit,
    SegmentationFault,
    Terminate,
    User1,
    User2,
    Other(&'a [u8]),
}

macro_rules! signal {
    { $($s:literal = $v:ident)* } => {
        impl<'a> From<&'a [u8]> for Signal<'a> {
            fn from(s: &'a [u8]) -> Self {
                match s {
                    $($s => Self::$v,)*
                    s => Self::Other(s),
                }
            }
        }

        impl<'a> From<Signal<'a>> for &'a [u8] {
            fn from(s: Signal<'a>) -> Self {
                match s {
                    $(Signal::$v => $s,)*
                    Signal::Other(s) => s,
                }
            }
        }
    };
}

signal! {
    b"ABRT" = Abort
    b"ALRM" = Alarm
    b"FPE" = FloatingPointException
    b"HUP" = Hangup
    b"ILL" = Illegal
    b"INT" = Interrupt
    b"KILL" = Kill
    b"PIPE" = Pipe
    b"QUIT" = Quit
    b"SEGV" = SegmentationFault
    b"TERM" = Terminate
    b"USR1" = User1
    b"USR2" = User2
}
