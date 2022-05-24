//! # Pure Rust implementation of the SSH protocol based on [RFC 4253]
//!
//! - Curve25519 ([RFC 8731])
//! - `chacha20-poly1305@openssh.com`
//!
//! [RFC 4253]: https://datatracker.ietf.org/doc/html/rfc4253
//! [RFC 5656]: https://datatracker.ietf.org/doc/html/rfc5656
//! [RFC 8731]: https://www.ietf.org/rfc/rfc8731.html

#![cfg_attr(not(test), no_std)]
// TODO there is one piece of code in key_exchange.rs that can _probably_ be written
// in an entirely safe way.
//#![forbid(unsafe_code)]

pub mod cipher;
pub mod client;
pub mod data;
pub mod identifier;
pub mod key_exchange;
pub mod message;
pub mod packet;
