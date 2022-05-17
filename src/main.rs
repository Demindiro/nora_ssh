use std::io::{Read, Write};
use std::net::TcpListener;

#[derive(Debug)]
enum ParseIdentError<R> {
    IdentifierTooLong,
    IncompatibleProtocol,
    Other(R),
}

const MAX_IDENT_LEN: usize = 255 - b"\r\n".len();

#[derive(Clone, Copy)]
struct Identifier<'a>(&'a [u8]);

impl<'a> Identifier<'a> {
    pub fn new(ident: &'a [u8]) -> Option<Self> {
        (ident.len() <= MAX_IDENT_LEN).then(|| Self(ident))
    }

    pub fn parse<R, F>(
        mut read: F,
        buf: &'a mut [u8; MAX_IDENT_LEN],
    ) -> Result<Self, ParseIdentError<R>>
    where
        F: FnMut() -> Result<u8, R>,
    {
        let mut read = || read().map_err(ParseIdentError::Other);
        // SSH-protoversion-softwareversion SP comments CR LF
        // protocol version MUST be "2.0"

        // TODO this is overcomplicated, we can just check if each line
        // starts with SSH- or not (a line ends with CR LF)
        // Match for "SSH-" first
        enum State {
            None,
            S,
            SS,
            SSH,
        }
        let mut state = State::None;
        loop {
            state = match (state, read()?) {
                (State::None, b'S') => State::S,
                (State::S, b'S') => State::SS,
                (State::SS, b'S') => State::SS,
                (State::SS, b'H') => State::SSH,
                (State::SSH, b'-') => break,
                _ => State::None,
            };
        }

        // Match "2.0" as protocol
        match [read()?, read()?, read()?, read()?] {
            [b'2', b'.', b'0', b'-'] => {}
            _ => return Err(ParseIdentError::IncompatibleProtocol),
        }

        let mut got_cr = false;
        let mut i = 0;
        let mut push = |c| {
            buf.get_mut(i)
                .ok_or(ParseIdentError::IdentifierTooLong)
                .map(|r| {
                    *r = c;
                    i += 1;
                })
        };
        b"SSH-2.0-".iter().copied().try_for_each(&mut push)?;
        loop {
            got_cr = match (got_cr, read()?) {
                (false, b'\r') => true,
                (true, b'\r') => {
                    push(b'\r')?;
                    true
                }
                (true, b'\n') => break,
                (false, c) => {
                    push(c)?;
                    false
                }
                (true, c) => {
                    push(b'\r')?;
                    push(c)?;
                    false
                }
            }
        }

        Ok(Self(&buf[..i]))
    }

    pub fn send<R, F>(self, send: F) -> Result<(), R>
    where
        F: FnMut(u8) -> Result<(), R>,
    {
        [self.0, b"\r\n"]
            .iter()
            .copied()
            .flatten()
            .copied()
            .try_for_each(send)
    }
}

impl AsRef<[u8]> for Identifier<'_> {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

struct Packet<'a> {
    buf: &'a [u8],
}

impl<'a> Packet<'a> {
    fn parse<R, F>(
        mut read: F,
        buf: &'a mut [u8],
    ) -> Result<(Self, &'a mut [u8]), PacketParseError<R>>
    where
        F: FnMut(&mut [u8]) -> Result<(), R>,
    {
        let mut read = move |b: &mut _| read(b).map_err(PacketParseError::Other);
        let mut len = [0; 4];
        read(&mut len)?;
        let len = u32::from_be_bytes(len).try_into().unwrap();
        if len > buf.len() {
            return Err(PacketParseError::TooLarge(len));
        } else if len < 8 {
            return Err(PacketParseError::TooSmall(len));
        }
        let (buf, rem) = buf.split_at_mut(len);
        read(buf)?;
        let padding = buf[0];
        let buf = &mut buf[1..len - usize::from(padding)];
        Ok((Self { buf }, rem))
    }

    fn payload(&self) -> &[u8] {
        self.buf
    }

    fn wrap(payload: &'a [u8]) -> Self {
        Self { buf: payload }
    }

    fn send<R, F>(&self, mut send: F, cipher_block_size: usize, mac: Option<Mac>) -> Result<(), R>
    where
        F: FnMut(&[u8]) -> Result<(), R>,
    {
        // TODO use a RNG to vary the amount of padding bytes & to vary the contents of it.
        // total length must be a multiple of the cipher block size or 8
        let padding = cipher_block_size.max(8);
        debug_assert_eq!(padding.count_ones(), 1, "padding must be a multiple of 2");
        let total_len = (4 + 1 + self.buf.len() + padding - 1) & !(padding - 1);
        let packet_len = total_len - 4;
        // There must be at least 4 bytes of padding
        let (padding_len, packet_len) = match packet_len - self.buf.len() - 1 {
            l if l < 4 => (l + padding, packet_len + padding),
            l => (l, packet_len),
        };
        send(&u32::try_from(packet_len).unwrap().to_be_bytes())?;
        send(&u8::try_from(padding_len).unwrap().to_be_bytes())?;
        send(self.buf)?;
        for _ in 0..padding_len {
            send(&[0])?;
        }
        match mac {
            None => {}
            // The Rust compiler is somewhat retarded.
            Some(_) => unreachable!(),
        }
        Ok(())
    }
}

enum Mac {}

#[derive(Debug)]
enum PacketParseError<R> {
    TooLarge(usize),
    TooSmall(usize),
    Other(R),
}

fn split(data: &[u8], i: usize) -> Option<(&[u8], &[u8])> {
    (data.len() >= i).then(|| data.split_at(i))
}

fn name_list(data: &[u8]) -> Option<(&[u8], &[u8])> {
    let (len, data) = split(data, 4)?;
    let len = u32::from_be_bytes(len.try_into().unwrap())
        .try_into()
        .unwrap();
    split(data, len)
}

fn make_string<'a>(buf: &'a mut [u8], s: &[u8]) -> Option<(&'a mut [u8], &'a mut [u8])> {
    buf.get_mut(..4)?
        .copy_from_slice(&u32::try_from(s.len()).unwrap().to_be_bytes());
    buf.get_mut(4..4 + s.len())?.copy_from_slice(s);
    Some(buf.split_at_mut(4 + s.len()))
}

fn make_pos_mpint<'a>(buf: &'a mut [u8], mut s: &[u8]) -> Option<(&'a mut [u8], &'a mut [u8])> {
    // Remove redundant zeroes
    while s.get(0) == Some(&0) {
        s = &s[1..];
    }
    // Prepend a zero to ensure the number is interpreted as positive
    let i = if s.get(0).map_or(false, |&c| c & 0x80 != 0) {
        *buf.get_mut(4)? = 0;
        1
    } else {
        0
    };
    buf.get_mut(..4)?
        .copy_from_slice(&u32::try_from(i + s.len()).unwrap().to_be_bytes());
    buf.get_mut(4 + i..4 + i + s.len())?.copy_from_slice(s);
    Some(buf.split_at_mut(4 + i + s.len()))
}

struct KeyExchangeInit<'a> {
    kex_algorithms: &'a [u8],
    server_host_key_algorithms: &'a [u8],
    encryption_algorithms_client_to_server: &'a [u8],
    encryption_algorithms_server_to_client: &'a [u8],
    mac_algorithms_client_to_server: &'a [u8],
    mac_algorithms_server_to_client: &'a [u8],
    compression_algorithms_client_to_server: &'a [u8],
    compression_algorithms_server_to_client: &'a [u8],
    languages_client_to_server: &'a [u8],
    languages_server_to_client: &'a [u8],
    first_kex_packet_follows: bool,
}

macro_rules! name_list {
    ($v:ident) => {
        fn $v(&self) -> impl Iterator<Item = &'a [u8]> {
            self.$v.split(|&c| c == b',')
        }
    };
}

impl<'a> KeyExchangeInit<'a> {
    fn parse(data: &'a [u8]) -> Result<Self, KeyExchangeInitParseError> {
        // Skip cookie
        let split = |data, i| split(data, i).ok_or(KeyExchangeInitParseError::Truncated);
        let name_list = |data| name_list(data).ok_or(KeyExchangeInitParseError::Truncated);
        let (_cookie, data) = split(data, 16)?;
        let (kex_algorithms, data) = name_list(data)?;
        let (server_host_key_algorithms, data) = name_list(data)?;
        let (encryption_algorithms_client_to_server, data) = name_list(data)?;
        let (encryption_algorithms_server_to_client, data) = name_list(data)?;
        let (mac_algorithms_client_to_server, data) = name_list(data)?;
        let (mac_algorithms_server_to_client, data) = name_list(data)?;
        let (compression_algorithms_client_to_server, data) = name_list(data)?;
        let (compression_algorithms_server_to_client, data) = name_list(data)?;
        let (languages_client_to_server, data) = name_list(data)?;
        let (languages_server_to_client, data) = name_list(data)?;
        // TODO it seems OpenSSH doesn't send this field?
        let (first_kex_packet_follows, data) = split(data, 1)?;
        let (zero, data) = split(data, 4)?;
        if zero != &[0; 4] {
            return Err(KeyExchangeInitParseError::NoTrailingZero);
        }
        if !data.is_empty() {
            return Err(KeyExchangeInitParseError::Unread);
        }
        Ok(Self {
            kex_algorithms,
            server_host_key_algorithms,
            encryption_algorithms_client_to_server,
            encryption_algorithms_server_to_client,
            mac_algorithms_client_to_server,
            mac_algorithms_server_to_client,
            compression_algorithms_client_to_server,
            compression_algorithms_server_to_client,
            languages_client_to_server,
            languages_server_to_client,
            first_kex_packet_follows: first_kex_packet_follows[0] != 0,
        })
    }

    fn send<R, F>(&self, mut send: F) -> Result<(), R>
    where
        F: FnMut(&[u8]) -> Result<(), R>,
    {
        let mut send = |data: &[u8]| {
            send(&u32::try_from(data.len()).unwrap().to_be_bytes())?;
            send(data)
        };
        // FIXME cookie has to be randomized
        send(&[Message::KEXINIT])?;
        send(&[0; 16])?;
        send(self.kex_algorithms)?;
        send(self.server_host_key_algorithms)?;
        send(self.encryption_algorithms_client_to_server)?;
        send(self.encryption_algorithms_server_to_client)?;
        send(self.mac_algorithms_client_to_server)?;
        send(self.mac_algorithms_server_to_client)?;
        send(self.compression_algorithms_client_to_server)?;
        send(self.compression_algorithms_server_to_client)?;
        send(self.languages_client_to_server)?;
        send(self.languages_server_to_client)?;
        send(&[u8::from(self.first_kex_packet_follows), 0, 0, 0, 0])
    }

    fn new_payload<'i>(
        buf: &mut [u8],
        kex_algorithms: impl Iterator<Item = &'i [u8]>,
        server_host_key_algorithms: impl Iterator<Item = &'i [u8]>,
        encryption_algorithms_client_to_server: impl Iterator<Item = &'i [u8]>,
        encryption_algorithms_server_to_client: impl Iterator<Item = &'i [u8]>,
        mac_algorithms_client_to_server: impl Iterator<Item = &'i [u8]>,
        mac_algorithms_server_to_client: impl Iterator<Item = &'i [u8]>,
        compression_algorithms_client_to_server: impl Iterator<Item = &'i [u8]>,
        compression_algorithms_server_to_client: impl Iterator<Item = &'i [u8]>,
        languages_client_to_server: impl Iterator<Item = &'i [u8]>,
        languages_server_to_client: impl Iterator<Item = &'i [u8]>,
    ) -> (&mut [u8], &mut [u8]) {
        fn name_list<'j>(
            buf: &mut [u8],
            iter: impl Iterator<Item = &'j [u8]>,
            none: bool,
        ) -> usize {
            let (len, buf) = buf.split_at_mut(4);
            let mut i = 0;
            let mut push = |b| {
                buf[i] = b;
                i += 1;
            };
            for (i, s) in iter.enumerate() {
                (i != 0).then(|| push(b','));
                s.iter().for_each(|&c| push(c));
            }
            if none && i == 0 {
                buf[..4].copy_from_slice(b"none");
                i = 4;
            }
            len.copy_from_slice(&u32::try_from(i).unwrap().to_be_bytes());
            4 + i
        }
        buf[0] = Message::KEXINIT;
        let i = 17; // message type + cookie
        let i = name_list(&mut buf[i..], kex_algorithms, true) + i;
        let i = name_list(&mut buf[i..], server_host_key_algorithms, true) + i;
        let i = name_list(&mut buf[i..], encryption_algorithms_client_to_server, true) + i;
        let i = name_list(&mut buf[i..], encryption_algorithms_server_to_client, true) + i;
        let i = name_list(&mut buf[i..], mac_algorithms_client_to_server, true) + i;
        let i = name_list(&mut buf[i..], mac_algorithms_server_to_client, true) + i;
        let i = name_list(&mut buf[i..], compression_algorithms_client_to_server, true) + i;
        let i = name_list(&mut buf[i..], compression_algorithms_server_to_client, true) + i;
        let i = name_list(&mut buf[i..], languages_client_to_server, false) + i;
        let i = name_list(&mut buf[i..], languages_server_to_client, false) + i;
        buf[i..i + 5].copy_from_slice(&[0; 5]); // guess + zero
        buf.split_at_mut(i + 5)
    }

    fn randomize_cookie(pkt: &mut [u8]) {
        pkt[1..17].copy_from_slice(b"kekeke");
    }

    name_list!(kex_algorithms);
    name_list!(server_host_key_algorithms);
    name_list!(encryption_algorithms_client_to_server);
    name_list!(encryption_algorithms_server_to_client);
    name_list!(mac_algorithms_client_to_server);
    name_list!(mac_algorithms_server_to_client);
    name_list!(compression_algorithms_client_to_server);
    name_list!(compression_algorithms_server_to_client);
    name_list!(languages_client_to_server);
    name_list!(languages_server_to_client);
}

#[derive(Debug)]
enum KeyExchangeInitParseError {
    Truncated,
    NoTrailingZero,
    Unread,
}

struct KeyExchangeEcdhInit<'a> {
    client_ephermal_public_key: &'a [u8; 32],
}

impl<'a> KeyExchangeEcdhInit<'a> {
    fn parse(data: &'a [u8]) -> Result<Self, KeyExchangeEcdhInitParseError> {
        let (len, data) = split(data, 4).ok_or(KeyExchangeEcdhInitParseError::Truncated)?;
        let len = u32::from_be_bytes(len.try_into().unwrap());
        if len != 32 {
            Err(KeyExchangeEcdhInitParseError::BadLength)
        } else if data.len() < 32 {
            Err(KeyExchangeEcdhInitParseError::Truncated)
        } else if data.len() > 32 {
            Err(KeyExchangeEcdhInitParseError::Unread)
        } else {
            Ok(Self {
                client_ephermal_public_key: data.try_into().unwrap(),
            })
        }
    }

    fn into_public_key(self) -> x25519_dalek::PublicKey {
        x25519_dalek::PublicKey::from(*self.client_ephermal_public_key)
    }
}

#[derive(Debug)]
enum KeyExchangeEcdhInitParseError {
    Truncated,
    BadLength,
    Unread,
}

#[derive(Debug)]
struct KeyExchangeEcdhReply<'a> {
    server_public_key: &'a [u8; 32],
    server_ephermal_public_key: &'a [u8; 32],
    exchange_hash_signature: &'a [u8; 64],
}

impl<'a> KeyExchangeEcdhReply<'a> {
    fn new_payload(
        buf: &'a mut [u8],
        server_public_key: &'a ecdsa::VerifyingKey<p256::NistP256>,
        server_ephermal_public_key: &'a x25519_dalek::PublicKey,
        exchange_hash_signature: &'a ecdsa::Signature<p256::NistP256>,
    ) -> (&'a mut [u8], &'a mut [u8]) {
        let mut keybuf = [0; 128];
        let mut blob = [0; 128];

        let (ty, b) = buf.split_first_mut().unwrap();
        *ty = Message::KEX_ECDH_REPLY;

        let (_, b) = Self::server_host_key(b, server_public_key);

        let (_, b) = make_string(b, server_ephermal_public_key.as_bytes()).unwrap();

        // signature
        use ecdsa::signature::Signature;
        let kb = &mut keybuf[..];
        let (_, kb) = make_string(kb, b"ecdsa-sha2-nistp256").unwrap();
        let bl = &mut blob[..];
        let (r, s) = &exchange_hash_signature.split_bytes();
        let (_, bl) = make_pos_mpint(bl, r).unwrap();
        let (_, bl) = make_pos_mpint(bl, s).unwrap();
        let bl = bl.len();
        let (_, kb) = make_string(kb, &blob[..blob.len() - bl]).unwrap();
        let kb = kb.len();
        let (_, b) = make_string(b, &keybuf[..keybuf.len() - kb]).unwrap();

        let b = b.len();
        buf.split_at_mut(buf.len() - b)
    }

    fn server_host_key<'i>(
        buf: &'i mut [u8],
        key: &ecdsa::VerifyingKey<p256::NistP256>,
    ) -> (&'i mut [u8], &'i mut [u8]) {
        let mut keybuf = [0; 128];
        let kb = &mut keybuf;
        let (_, kb) = make_string(kb, b"ecdsa-sha2-nistp256").unwrap();
        let (_, kb) = make_string(kb, b"nistp256").unwrap();
        // OpenSSH doesn't like compressed points.
        let (_, kb) = make_string(kb, key.to_encoded_point(false).as_bytes()).unwrap();
        let kb = kb.len();
        let (_, b) = make_string(buf, &keybuf[..keybuf.len() - kb]).unwrap();
        let b = b.len();
        buf.split_at_mut(buf.len() - b)
    }
}

enum Message<'a> {
    KeyExchangeInit(KeyExchangeInit<'a>),
    KeyExchangeEcdhInit(KeyExchangeEcdhInit<'a>),
    NewKeys,
}

macro_rules! msg_as {
    ($v:ident -> $f:ident, $g:ident) => {
        fn $f(&self) -> Option<&$v<'a>> {
            match self {
                Self::$v(v) => Some(v),
                _ => None,
            }
        }

        fn $g(self) -> Option<$v<'a>> {
            match self {
                Self::$v(v) => Some(v),
                _ => None,
            }
        }
    };
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

    fn parse(data: &'a [u8]) -> Result<Self, MessageParseError> {
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
            Self::NEWKEYS => {
                if data.len() == 1 {
                    Ok(Message::NewKeys)
                } else {
                    Err(MessageParseError::Unread)
                }
            }
            Self::KEX_ECDH_INIT => KeyExchangeEcdhInit::parse(&data[1..])
                .map(Self::KeyExchangeEcdhInit)
                .map_err(MessageParseError::KeyExchangeEcdhInitParseError),
            Self::KEX_ECDH_REPLY => todo!(),
            ty => Err(MessageParseError::UnknownMessageType(ty)),
        }
    }

    msg_as!(KeyExchangeInit -> as_kex_init, into_kex_init);
    msg_as!(KeyExchangeEcdhInit -> as_kex_ecdh_init, into_kex_ecdh_init);

    fn is_new_keys(&self) -> bool {
        match self {
            Self::NewKeys => true,
            _ => false,
        }
    }
}

#[derive(Debug)]
enum MessageParseError {
    NoMessageType,
    Unread,
    UnknownMessageType(u8),
    KeyExchangeInitParseError(KeyExchangeInitParseError),
    KeyExchangeEcdhInitParseError(KeyExchangeEcdhInitParseError),
}

fn main() {
    use rand::SeedableRng;
    let mut rng = rand::rngs::StdRng::seed_from_u64(0);
    let server_secret = ecdsa::SigningKey::<p256::NistP256>::random(&mut rng);
    let server_public = server_secret.verifying_key();

    let mut kexinit = [0; 2048];
    let (kexinit, _) = KeyExchangeInit::new_payload(
        &mut kexinit,
        ["curve25519-sha256".as_ref()].into_iter(),
        ["ecdsa-sha2-nistp256".as_ref()].into_iter(),
        ["chacha20-poly1305@openssh.com".as_ref()].into_iter(),
        ["chacha20-poly1305@openssh.com".as_ref()].into_iter(),
        ["hmac-sha2-256".as_ref()].into_iter(),
        ["hmac-sha2-256".as_ref()].into_iter(),
        [].into_iter(),
        [].into_iter(),
        [].into_iter(),
        [].into_iter(),
    );
    let mut l = 0;
    Packet::wrap(kexinit)
        .send::<(), _>(|d| Ok(l += d.len()), 0, None)
        .unwrap();
    dbg!(l);
    assert_eq!(l & 7, 0);

    let l = TcpListener::bind("127.0.0.1:2222").unwrap();
    let server_ident = Identifier::new(b"SSH-2.0-nora_ssh example").unwrap();
    for c in l.incoming().map(Result::unwrap) {
        let server_ephermal_secret = x25519_dalek::EphemeralSecret::new(&mut rng);
        let server_ephermal_public = x25519_dalek::PublicKey::from(&server_ephermal_secret);

        let mut hash_msg_og = [0; 1 << 12];
        let hash_msg = &mut hash_msg_og[..];

        // send id + kexinit
        let c = std::cell::RefCell::new(c);
        let send = |b| c.borrow_mut().write_all(&[b]);
        let recv = || {
            let mut b = [0];
            c.borrow_mut().read_exact(&mut b).map(|()| b[0])
        };
        server_ident.send(send).unwrap();
        Packet::wrap(kexinit)
            .send(|d| c.borrow_mut().write_all(d), 0, None)
            .unwrap();

        // recv id + kexinit
        let mut ident = [0; MAX_IDENT_LEN];
        let client_ident = Identifier::parse(recv, &mut ident).unwrap();
        let (_, hash_msg) = make_string(hash_msg, client_ident.as_ref()).unwrap();
        let (_, hash_msg) = make_string(hash_msg, server_ident.as_ref()).unwrap();

        let mut buf = [0; 1 << 16];
        let (pkt, rem) = Packet::parse(|b| c.borrow_mut().read_exact(b), &mut buf).unwrap();
        let (_, hash_msg) = make_string(hash_msg, pkt.payload()).unwrap();
        let (_, hash_msg) = make_string(hash_msg, kexinit).unwrap();
        let (_, hash_msg) = KeyExchangeEcdhReply::server_host_key(hash_msg, &server_public);
        let msg = Message::parse(pkt.payload())
            .unwrap()
            .into_kex_init()
            .unwrap();
        if msg
            .kex_algorithms()
            .find(|s| s == b"curve25519-sha256")
            .is_none()
        {
            todo!()
        }
        if msg
            .server_host_key_algorithms()
            .find(|s| s == b"ecdsa-sha2-nistp256")
            .is_none()
        {
            todo!()
        }
        if msg
            .encryption_algorithms_client_to_server()
            .find(|s| s == b"chacha20-poly1305@openssh.com")
            .is_none()
        {
            todo!()
        }
        if msg
            .encryption_algorithms_server_to_client()
            .find(|s| s == b"chacha20-poly1305@openssh.com")
            .is_none()
        {
            todo!()
        }
        if msg
            .mac_algorithms_client_to_server()
            .find(|s| s == b"hmac-sha2-256")
            .is_none()
        {
            todo!()
        }
        if msg
            .mac_algorithms_server_to_client()
            .find(|s| s == b"hmac-sha2-256")
            .is_none()
        {
            todo!()
        }

        let (pkt, rem) = Packet::parse(|b| c.borrow_mut().read_exact(b), &mut buf).unwrap();
        let client_key = Message::parse(pkt.payload())
            .unwrap()
            .into_kex_ecdh_init()
            .unwrap()
            .into_public_key();

        let (_, hash_msg) = make_string(hash_msg, client_key.as_bytes()).unwrap();
        let (_, hash_msg) = make_string(hash_msg, server_ephermal_public.as_bytes()).unwrap();

        let shared_secret = server_ephermal_secret.diffie_hellman(&client_key);
        let (_, hash_msg) = make_pos_mpint(hash_msg, shared_secret.as_bytes()).unwrap();
        dbg!(server_ephermal_public.as_bytes().len());
        dbg!(shared_secret.as_bytes().len());

        use sha2::Digest;
        let l = hash_msg.len();
        let hash_msg = &hash_msg_og[..hash_msg_og.len() - l];
        dbg!(hash_msg.len());
        let hash = sha2::Sha256::digest(hash_msg);
        use ecdsa::signature::Signer;
        let sig = server_secret.sign(&hash);

        let mut buf = [0; 1 << 12];
        let (payload, _) = KeyExchangeEcdhReply::new_payload(
            &mut buf,
            &server_public,
            &server_ephermal_public,
            &sig,
        );
        dbg!(&payload.len());
        Packet::wrap(payload)
            .send(|d| c.borrow_mut().write_all(d), 8, None)
            .unwrap();

        // IV client -> server = HASH(K || H || "A" || session_id)
        // IV server -> client = HASH(K || H || "B" || session_id)
        // Encryption key client -> server = HASH(K || H || "C" || session_id)
        // Encryption key server -> client = HASH(K || H || "D" || session_id)
        // Integrity key client -> server = HASH(K || H || "E" || session_id)
        // Integrity key server -> client = HASH(K || H || "F" || session_id)
        //
        // K1 = HASH(K || H || X || session_id)
        // K2 = HASH(K || H || K1)
        // K3 = HASH(K || H || K1 || K2)
        // ...
        // key = K1 || K2 || ...
        let session_id = hash;
        let mut digest = [0; 128];

        let mut iv_in = [0; 12];
        let mut key_in = [0; 64];

        let d = &mut digest;
        let (_, d) = make_pos_mpint(d, shared_secret.as_bytes()).unwrap();
        d[..32].copy_from_slice(&hash);
        d[32] = b'A';
        d[33..65].copy_from_slice(&session_id);
        let d = d.len() - 65;
        iv_in.copy_from_slice(&sha2::Sha256::digest(&digest[..digest.len() - d])[..12]);

        let d = &mut digest;
        let (_, d) = make_pos_mpint(d, shared_secret.as_bytes()).unwrap();
        d[..32].copy_from_slice(&hash);
        d[32] = b'C';
        d[33..65].copy_from_slice(&session_id);
        let d = d.len() - 65;
        key_in[..32].copy_from_slice(&sha2::Sha256::digest(&digest[..digest.len() - d]));

        let d = &mut digest;
        let (_, d) = make_pos_mpint(d, shared_secret.as_bytes()).unwrap();
        d[..32].copy_from_slice(&hash);
        d[32..64].copy_from_slice(&key_in[..32]);
        let d = d.len() - 64;
        key_in[32..].copy_from_slice(&sha2::Sha256::digest(&digest[..digest.len() - d]));

        use chacha20::cipher::KeyIvInit;
        let (k2_in, k1_in) = key_in.split_at(32);
        use chacha20poly1305::aead::NewAead;
        let k1_in = chacha20::Key::from_slice(&k1_in);
        let k2_in = chacha20poly1305::Key::from_slice(&k2_in);

        Packet::wrap(&[Message::NEWKEYS])
            .send(|d| c.borrow_mut().write_all(d), 0, None)
            .unwrap();
        let (pkt, rem) = Packet::parse(|b| c.borrow_mut().read_exact(b), &mut buf).unwrap();
        assert!(Message::parse(pkt.payload()).unwrap().is_new_keys());

        let mut send_counter @ mut recv_counter = 3u64;

        loop {
            //send_counter = send_counter.checked_add(1).expect("counter overflowed");
            //recv_counter = recv_counter.checked_add(1).expect("counter overflowed");
            let nonce = &recv_counter.to_be_bytes();
            let nonce = chacha20::LegacyNonce::from_slice(nonce);

            let mut buf = [0; 4 + (1 << 15) + 16];
            let (len_b, pkt) = buf.split_at_mut(4);
            let mut cipher1_in = chacha20::ChaCha20Legacy::new(&k1_in, &nonce);
            c.borrow_mut().read_exact(len_b).unwrap();
            dbg!(&len_b);
            let mut len = [0; 4];
            len.copy_from_slice(len_b);
            //use chacha20poly1305::aead::Aead;
            use chacha20::cipher::StreamCipher;
            cipher1_in.apply_keystream(&mut len);
            let len = u32::from_be_bytes(len.try_into().unwrap());
            dbg!(len);

            let len = usize::try_from(len).unwrap();
            let pkt = &mut pkt[..len + 16];
            c.borrow_mut().read_exact(pkt).unwrap();
            dbg!(&pkt);
            let (pkt, tag_b) = buf[..4 + len + 16].split_at_mut(4 + len);
            let mut tag = [0; 16];
            tag.copy_from_slice(tag_b);
            tag_b.fill(0);
            let pkt = &mut buf[..4 + len + 16];

            let mut cipher2_in = chacha20::ChaCha20Legacy::new(&k2_in, &nonce);

            let mut mac_key = [0; 32];
            cipher2_in.apply_keystream(&mut mac_key);
            dbg!(&mac_key);
            let mac_key = poly1305::Key::from_slice(&mac_key);
            use poly1305::universal_hash::NewUniversalHash;
            use poly1305::universal_hash::UniversalHash;
            let mut mac = poly1305::Poly1305::new(&mac_key);
            dbg!(tag);
            dbg!(mac.compute_unpadded(&pkt[..4 + len]).into_bytes());
            //mac.update_padded(&mut buf[..4 + len]);
            //dbg!(mac.finalize().into_bytes());

            let mut cipher2_in = chacha20::ChaCha20LegacyCore::new(&k2_in, &nonce);
            use chacha20::cipher::StreamCipherSeekCore;
            cipher2_in.set_block_pos(1);
            let mut cipher2_in = chacha20::cipher::StreamCipherCoreWrapper::from_core(cipher2_in);
            cipher2_in.apply_keystream(&mut pkt[4..]);
            dbg!(&mut pkt[..]);

            /*
            let cipher2_in = chacha20poly1305::ChaCha20Poly1305::new(&k2_in);
            use chacha20poly1305::aead::AeadInPlace;
            let mut dec = Vec::new();
            dbg!(pkt.len());
            cipher2_in
                .decrypt_in_place(chacha20poly1305::Nonce::from_slice(nonce), pkt, &mut dec)
                .unwrap();
            */

            //dbg!(dec);

            break;
            /*
            let (pkt, rem) = Packet::parse_chacha20poly1305(|b| {
                c.borrow_mut().read_exact(b)
            }, &mut buf).unwrap();
            pkt.payload();
            match Message::parse(pkt.payload()).unwrap() {
                _ => todo!(),
            }
            */
        }
    }
}
