//! # Pure Rust implementation of the SSH protocol based on [RFC 4253]
//!
//! - Curve25519 ([RFC 8731])
//! - `chacha20-poly1305@openssh.com`
//!
//! [RFC 4253]: https://datatracker.ietf.org/doc/html/rfc4253
//! [RFC 5656]: https://datatracker.ietf.org/doc/html/rfc5656
//! [RFC 8731]: https://www.ietf.org/rfc/rfc8731.html

#![feature(let_else)]
#![feature(never_type)]
#![feature(type_alias_impl_trait)]

mod arena;
pub mod cipher;
pub mod client;
pub mod data;
mod handler;
pub mod host;
pub mod identifier;
pub mod key_exchange;
pub mod message;
pub mod packet;
pub mod server;
mod sync;

pub use handler::Handler;
