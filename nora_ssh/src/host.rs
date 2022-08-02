use crate::{
    identifier::{self, ParseIdentError},
    packet::{self, PacketParseError},
};
use digest::Digest;
use ecdsa::{
    hazmat::SignPrimitive,
    signature::{Signature, Signer},
    PrimeCurve, SignatureSize, SigningKey, VerifyingKey,
};
use elliptic_curve::{
    ops::{Invert, Reduce},
    ProjectiveArithmetic, Scalar,
};
use futures::io::{self, AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use generic_array::ArrayLength;
use nora_ssh_core::{
    cipher::{ChaCha20Poly1305, Cipher, Error, CIPHER_NAMES},
    identifier::Identifier,
    key_exchange::{Direction, KeyMaterial, ALGORITHM_NAMES},
    message::{
        key_exchange::ecdh::{self, Key, KeyBlob, KeyExchangeDigest, SignatureBlob},
        KeyExchangeEcdhReply, KeyExchangeInit, Message, MessageParseError, NewKeys,
    },
    packet::{BlockSize, Packet, WrapRawError},
};
use rand::{CryptoRng, RngCore};
use subtle::CtOption;

pub trait SignKey
where
    Self: PrimeCurve + ProjectiveArithmetic + Clone,
    Scalar<Self>:
        Invert<Output = CtOption<Scalar<Self>>> + Reduce<Self::UInt> + SignPrimitive<Self>,
    SignatureSize<Self>: ArrayLength<u8>,
{
    fn name() -> &'static str;
}

pub struct HostKey<C>
where
    C: SignKey,
    Scalar<C>: Invert<Output = CtOption<Scalar<C>>> + Reduce<C::UInt> + SignPrimitive<C>,
    SignatureSize<C>: ArrayLength<u8>,
{
    public: VerifyingKey<C>,
    secret: SigningKey<C>,
}

impl<C> HostKey<C>
where
    C: SignKey,
    Scalar<C>: Invert<Output = CtOption<Scalar<C>>> + Reduce<C::UInt> + SignPrimitive<C>,
    SignatureSize<C>: ArrayLength<u8>,
{
    fn name(&self) -> &'static str {
        C::name()
    }
}

impl<C> From<SigningKey<C>> for HostKey<C>
where
    C: SignKey,
    C: PrimeCurve + ProjectiveArithmetic,
    Scalar<C>: Invert<Output = CtOption<Scalar<C>>> + Reduce<C::UInt> + SignPrimitive<C>,
    SignatureSize<C>: ArrayLength<u8>,
{
    fn from(secret: SigningKey<C>) -> Self {
        Self {
            public: secret.verifying_key(),
            secret,
        }
    }
}

pub struct Host<C>
where
    C: SignKey,
    Scalar<C>: Invert<Output = CtOption<Scalar<C>>> + Reduce<C::UInt> + SignPrimitive<C>,
    SignatureSize<C>: ArrayLength<u8>,
{
    identifier: Identifier<'static>,
    host_key: HostKey<C>,
}

impl<C> Host<C>
where
    C: SignKey,
    Scalar<C>: Invert<Output = CtOption<Scalar<C>>> + Reduce<C::UInt> + SignPrimitive<C>,
    SignatureSize<C>: ArrayLength<u8>,
{
    pub fn new(identifier: Identifier<'static>, host_key: impl Into<HostKey<C>>) -> Self {
        Self {
            identifier,
            host_key: host_key.into(),
        }
    }
}

impl Host<p256::NistP256> {
    pub async fn handle_new_client<Read, Write, Rng>(
        &self,
        read: &mut Read,
        write: &mut Write,
        mut rng: Rng,
    ) -> Result<HostClient<ChaCha20Poly1305>, HandleNewClientError>
    where
        Read: AsyncRead + Unpin,
        Write: AsyncWrite + Unpin,
        Rng: CryptoRng + RngCore,
    {
        type D = sha2::Sha256;
        type DKeyMaterial = sha2::Sha256;

        let mut pkt_buf = Vec::new();
        pkt_buf.resize(1 << 16, 0);

        let exchange_hash = KeyExchangeDigest::<D>::default();

        // Send identifier + kexinit
        identifier::send(self.identifier, write)
            .await
            .map_err(HandleNewClientError::Write)?;
        let mut host_pkt = [0; 256];
        let host_pkt = Packet::wrap(
            &mut host_pkt,
            BlockSize::B8,
            true,
            |buf| {
                Message::KeyExchangeInit(KeyExchangeInit {
                    cookie: b"nomnommunchmunch",
                    kex_algorithms: b"curve25519-sha256".try_into().unwrap(),
                    server_host_key_algorithms: b"ecdsa-sha2-nistp256".try_into().unwrap(),
                    encryption_algorithms_client_to_server: b"chacha20-poly1305@openssh.com"
                        .try_into()
                        .unwrap(),
                    encryption_algorithms_server_to_client: b"chacha20-poly1305@openssh.com"
                        .try_into()
                        .unwrap(),
                    compression_algorithms_client_to_server: b"none".try_into().unwrap(),
                    compression_algorithms_server_to_client: b"none".try_into().unwrap(),
                    mac_algorithms_client_to_server: b"none".try_into().unwrap(),
                    mac_algorithms_server_to_client: b"none".try_into().unwrap(),
                    languages_client_to_server: b"".try_into().unwrap(),
                    languages_server_to_client: b"".try_into().unwrap(),
                    first_kex_packet_follows: false,
                })
                .serialize(buf)
                .unwrap()
                .0
                .len()
            },
            &mut rng,
        );
        write
            .write_all(host_pkt.as_raw())
            .await
            .map_err(HandleNewClientError::Write)?;

        // Receive id + kexinit
        let mut ident = [0; Identifier::MAX_LEN];
        let client_ident = identifier::parse(read, &mut ident)
            .await
            .map_err(HandleNewClientError::ParseIdentifierError)?;

        let exchange_hash = exchange_hash.update(&client_ident).update(&self.identifier);
        let pkt = packet::parse(&mut pkt_buf, read, true, BlockSize::B8)
            .await
            .map_err(HandleNewClientError::PacketParseError)?;
        let exchange_hash = exchange_hash
            .update(pkt.payload())
            .update(host_pkt.payload());

        let msg = Message::parse(pkt.payload())
            .map_err(HandleNewClientError::MessageParseError)?
            .into_kex_init()
            .ok_or(HandleNewClientError::ExpectedKeyExchangeInit)?;
        if !msg
            .kex_algorithms
            .iter()
            .any(|s| ALGORITHM_NAMES.iter().any(|&t| t == s))
            || !msg
                .server_host_key_algorithms
                .iter()
                .any(|s| s == self.host_key.name())
            || !msg
                .encryption_algorithms_client_to_server
                .iter()
                .any(|s| CIPHER_NAMES.iter().any(|&t| t == s))
            || !msg
                .encryption_algorithms_server_to_client
                .iter()
                .any(|s| CIPHER_NAMES.iter().any(|&t| t == s))
        // TODO we should handle the case where a HMAC needs to be selected if we're
        // not using chacha20-poly1305
        {
            return Err(HandleNewClientError::UnsupportedAlgorithms);
        }

        // Generate temporary key for exchanging the secret
        let server_ephermal_secret = x25519_dalek::EphemeralSecret::new(&mut rng);
        let server_ephermal_public = x25519_dalek::PublicKey::from(&server_ephermal_secret);

        // Receive the client's temporary key
        let pkt = packet::parse(&mut pkt_buf, read, true, BlockSize::B8)
            .await
            .map_err(HandleNewClientError::PacketParseError)?;
        let client_ephermal_public = Message::parse(pkt.payload())
            .unwrap()
            .into_kex_ecdh_init()
            .unwrap()
            .client_ephermal_public_key;
        let client_ephermal_public = <[u8; 32]>::try_from(client_ephermal_public).unwrap();
        let client_ephermal_public = x25519_dalek::PublicKey::from(client_ephermal_public);

        let server_public_key = self.host_key.public.to_encoded_point(false);
        let server_public_key = Key {
            name: b"ecdsa-sha2-nistp256",
            blob: KeyBlob {
                identifier: b"nistp256",
                // OpenSSH doesn't like compressed points.
                q: server_public_key.as_bytes(),
            },
        };

        // Compute shared secret
        let exchange_hash = exchange_hash
            .update(&mut pkt_buf, &server_public_key)
            .update(client_ephermal_public.as_bytes())
            .update(server_ephermal_public.as_bytes());
        let shared_secret = server_ephermal_secret.diffie_hellman(&client_ephermal_public);
        let hash = exchange_hash.update(shared_secret.as_bytes());
        let sig = self.host_key.secret.sign(&hash);

        let key_material = KeyMaterial::<DKeyMaterial>::new(*shared_secret.as_bytes(), hash.into());

        // send secret
        let pkt = Packet::wrap(
            &mut pkt_buf,
            BlockSize::B8,
            true,
            |buf| {
                let (r, s) = sig.split_bytes();
                Message::KeyExchangeEcdhReply(KeyExchangeEcdhReply {
                    server_public_key,
                    server_ephermal_public_key: server_ephermal_public.as_bytes(),
                    exchange_hash_signature: ecdh::Signature {
                        name: b"ecdsa-sha2-nistp256",
                        blob: SignatureBlob { r: &r, s: &s },
                    },
                })
                .serialize(buf)
                .unwrap()
                .0
                .len()
            },
            &mut rng,
        );
        write
            .write_all(pkt.into_raw(0))
            .await
            .map_err(HandleNewClientError::Write)?;

        let receive_cipher = In(ChaCha20Poly1305::from_key_material(
            &key_material,
            Direction::ClientToServer,
            3,
        ));
        let send_cipher = Out(ChaCha20Poly1305::from_key_material(
            &key_material,
            Direction::ServerToClient,
            3,
        ));

        // confirm
        let pkt = Packet::wrap(
            &mut pkt_buf,
            BlockSize::B8,
            true,
            |buf| Message::NewKeys(NewKeys).serialize(buf).unwrap().0.len(),
            &mut rng,
        );
        write
            .write_all(pkt.as_raw())
            .await
            .map_err(HandleNewClientError::Write)?;
        let pkt = packet::parse(&mut pkt_buf, read, true, BlockSize::B8)
            .await
            .map_err(HandleNewClientError::PacketParseError)?;
        Message::parse(pkt.payload())
            .unwrap()
            .into_new_keys()
            .ok_or(HandleNewClientError::ExpectedKeys)?;

        Ok(HostClient {
            receive_cipher,
            send_cipher,
            session_identifier: *hash.as_ref(),
        })
    }
}

#[derive(Debug)]
pub enum HandleNewClientError {
    ParseIdentifierError(ParseIdentError),
    MessageParseError(MessageParseError),
    PacketParseError(PacketParseError),
    ExpectedKeyExchangeInit,
    UnsupportedAlgorithms,
    ExpectedKeys,
    Read(io::Error),
    Write(io::Error),
}

pub struct Out<D: Cipher>(D);

impl<D: Cipher> Out<D> {
    pub async fn send<Io, F, Rng>(
        &mut self,
        buf: &mut [u8],
        fill: F,
        io: &mut Io,
        rng: Rng,
    ) -> Result<(), OutError>
    where
        Io: AsyncWrite + Unpin,
        F: FnOnce(&mut [u8]) -> usize,
        Rng: CryptoRng + RngCore,
    {
        let pkt = Packet::wrap(
            buf,
            self.0.block_size(),
            false, // TODO add method to Cipher
            |buf| fill(buf),
            rng,
        );
        let pkt = pkt.into_raw(self.0.tag_size());
        self.0.encrypt(pkt);
        io.write_all(pkt).await.map_err(OutError::Write)
    }
}

#[derive(Debug)]
pub enum OutError {
    Write(io::Error),
}

pub struct In<D: Cipher>(D);

impl<D: Cipher> In<D> {
    pub async fn recv<'s, 'a: 's, 'b: 's, Io>(
        &'s mut self,
        buf: &'a mut [u8],
        io: &'b mut Io,
    ) -> Result<&'a mut [u8], InError>
    where
        Io: AsyncReadExt + Unpin,
    {
        let (len, data) = buf.split_at_mut(4);
        io.read_exact(len).await.map_err(InError::Read)?;
        let lenb = self
            .0
            .decrypt_length(len.try_into().unwrap())
            .map_err(InError::Cipher)?;
        let len = u32::from_be_bytes(lenb).try_into().unwrap();
        let data = data
            .get_mut(..len + self.0.tag_size())
            .ok_or(InError::BufferTooSmall(len))?;
        io.read_exact(data).await.map_err(InError::Read)?;
        let data = &mut buf[..4 + len + self.0.tag_size()];
        self.0.decrypt_data(data).map_err(InError::Cipher)?;
        data[..4].copy_from_slice(&lenb);
        Packet::wrap_raw(buf, false, self.0.block_size())
            .map_err(InError::Packet)
            .map(Packet::into_payload)
    }
}

#[derive(Debug)]
pub enum InError {
    Packet(WrapRawError),
    BufferTooSmall(usize),
    Read(io::Error),
    Cipher(Error),
}

pub struct HostClient<D: Cipher> {
    receive_cipher: In<D>,
    send_cipher: Out<D>,
    session_identifier: [u8; 32],
}

impl<D: Cipher> HostClient<D> {
    pub fn session_identifier(&self) -> &[u8; 32] {
        &self.session_identifier
    }
}

impl<D: Cipher> HostClient<D> {
    pub fn into_send_receive(self) -> (Out<D>, In<D>) {
        (self.send_cipher, self.receive_cipher)
    }
}

impl SignKey for p256::NistP256 {
    fn name() -> &'static str {
        "ecdsa-sha2-nistp256"
    }
}
