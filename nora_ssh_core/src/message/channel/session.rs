//! Based on [RFC 4254 Section 5].
//!
//! [RFC 4254 Section 5]: https://datatracker.ietf.org/doc/html/rfc4254#section-5

use crate::data::{make_bool, make_string2, make_uint32, parse_bool, parse_string, parse_uint32};
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
        let parse_str = |data| parse_string(data).ok_or(ParseError::Truncated);
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

    pub fn serialize<'b>(&self, buf: &'b mut [u8]) -> Option<(&'static [u8], usize)> {
        match self {
            Self::Pty {
                terminal,
                char_width,
                char_height,
                pixel_width,
                pixel_height,
                modes,
            } => {
                let (a, buf) = make_string2(buf, terminal)?;
                let (b, buf) = make_uint32(buf, *char_width)?;
                let (c, buf) = make_uint32(buf, *char_height)?;
                let (d, buf) = make_uint32(buf, *pixel_width)?;
                let (e, buf) = make_uint32(buf, *pixel_height)?;
                let (f, _) = make_string2(buf, modes)?;
                Some((b"pty-req", a + b + c + d + e + f))
            }
            Self::X11 {
                single_connection,
                auth_protocol,
                auth_cookie,
                screen,
            } => {
                let (a, buf) = make_bool(buf, *single_connection)?;
                let (b, buf) = make_string2(buf, auth_protocol)?;
                let (c, buf) = make_string2(buf, auth_cookie)?;
                let (d, _) = make_uint32(buf, *screen)?;
                Some((b"x11-req", a + b + c + d))
            }
            Self::Env { name, value } => {
                let (a, buf) = make_string2(buf, name)?;
                let (b, _) = make_string2(buf, value)?;
                Some((b"env", a + b))
            }
            Self::Shell => Some((b"shell", 0)),
            Self::Exec { command } => {
                let (a, _) = make_string2(buf, command)?;
                Some((b"exec", a))
            }
            Self::Subsystem { name } => {
                let (a, _) = make_string2(buf, name)?;
                Some((b"subsystem", a))
            }
            Self::WindowChange {
                char_width,
                char_height,
                pixel_width,
                pixel_height,
            } => {
                let (a, buf) = make_uint32(buf, *char_width)?;
                let (b, buf) = make_uint32(buf, *char_height)?;
                let (c, buf) = make_uint32(buf, *pixel_width)?;
                let (d, _) = make_uint32(buf, *pixel_height)?;
                Some((b"window-change", a + b + c + d))
            }
            Self::XonXoff { on } => {
                let (a, _) = make_bool(buf, *on)?;
                Some((b"xon-xoff", a))
            }
            Self::Signal { signal } => {
                let (a, _) = make_string2(buf, (*signal).into())?;
                Some((b"signal", a))
            }
            Self::ExitStatus { status } => {
                let (a, _) = make_uint32(buf, *status)?;
                Some((b"exit-status", a))
            }
            Self::ExitSignal {
                signal,
                core_dumped,
                message,
                language,
            } => {
                let (a, buf) = make_string2(buf, (*signal).into())?;
                let (b, buf) = make_bool(buf, *core_dumped)?;
                let (c, buf) = make_string2(buf, message.as_ref())?;
                let (d, _) = make_string2(buf, language)?;
                Some((b"exit-signal", a + b + c + d))
            }
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

#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
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

#[cfg(test)]
mod test {
    use super::{super::super::Message, *};

    macro_rules! sds {
        ($ty:literal | $name:ident => $v:ident = $($e:ident : $val:expr,)*) => {
            #[test]
            fn $name() {
                let mut a @ mut b = [0; 2048];
                let (t, i) = SessionRequest::$v { $($e : $val,)* }.serialize(&mut a).unwrap();
                assert_eq!(t, $ty);
                let a = &a[..i];
                let i = SessionRequest::parse(t, a).unwrap().serialize(&mut b).unwrap().1;
                assert_eq!(a, &b[..i]);
            }
        };
    }

    sds!(b"pty-req" | serialize_deserialize_serialize_pty => Pty = terminal: b"v8999", char_width: 2032, char_height: 29302, pixel_width: 290323, pixel_height: 923029, modes: b"ofzkfeo,fezfz",);
    sds!(b"x11-req" | serialize_deserialize_serialize_x11 => X11 = single_connection: true, auth_protocol: b"kregokgoek", auth_cookie: b"rpokge", screen: 2093,);
    sds!(b"env" | serialize_deserialize_serialize_env => Env = name: b"aa", value: b"abc",);
    sds!(b"shell" | serialize_deserialize_serialize_shell => Shell = );
    sds!(b"exec" | serialize_deserialize_serialize_exec => Exec = command: b"abracadabra",);
    sds!(b"subsystem" | serialize_deserialize_serialize_subsystem => Subsystem = name: b"quack",);
    sds!(b"window-change" | serialize_deserialize_serialize_window_change => WindowChange = char_width: 2032, char_height: 29302, pixel_width: 290323, pixel_height: 923029,);
    sds!(b"xon-xoff" | serialize_deserialize_serialize_xon_xoff => XonXoff = on: true,);
    sds!(b"signal" | serialize_deserialize_serialize_signal => Signal = signal: Signal::User1,);
    sds!(b"exit-status" | serialize_deserialize_serialize_exit_status => ExitStatus = status: 403,);
    sds!(b"exit-signal" | serialize_deserialize_serialize_exit_signal => ExitSignal = signal: Signal::Other(b"kgroegre"), core_dumped: false, message: "goerkogre", language: b"",);
}
