use crate::{
    cipher::{ChaCha20Poly1305, Cipher, Error, CIPHER_NAMES},
    data::{make_pos_mpint, make_string_len},
    identifier::{Identifier, ParseIdentError},
    key_exchange::{Direction, KeyMaterial, ALGORITHM_NAMES},
    message::{KeyExchangeEcdhReply, Message, MessageParseError, NewKeys},
    packet::{BlockSize, Packet, PacketParseError, WrapRawError},
};
use core::{fmt, future::Future};
use digest::Digest;
use ecdsa::{
    hazmat::SignPrimitive, signature::Signer, PrimeCurve, SignatureSize, SigningKey, VerifyingKey,
};
use elliptic_curve::{
    ops::{Invert, Reduce},
    ProjectiveArithmetic, Scalar,
};
use futures::io;
use generic_array::ArrayLength;
use rand::{CryptoRng, RngCore};
use subtle::CtOption;

pub trait SignKey
where
    Self: PrimeCurve + ProjectiveArithmetic,
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
    pub async fn handle_new_client<Io, Rng>(
        &self,
        io: &mut Io,
        mut rng: Rng,
    ) -> Result<HostClient<crate::cipher::ChaCha20Poly1305>, HandleNewClientError>
    where
        Io: io::AsyncReadExt + io::AsyncWriteExt + Unpin,
        Rng: CryptoRng + RngCore,
    {
        type D = sha2::Sha256;
        type DKeyMaterial = sha2::Sha256;

        let mut pkt_buf = [0; 1 << 16];

        let mut exchange_hash = D::new();
        let update_string = |hash: &mut D, s: &[u8]| {
            hash.update(&make_string_len(s));
            hash.update(s);
        };
        let update_pos_mpint = |hash: &mut D, s: &[u8]| {
            let mut buf = [0; 4 + 1 + 32];
            let l = make_pos_mpint(&mut buf, s).unwrap();
            hash.update(&buf[..l]);
        };

        // Send identifier + kexinit
        self.identifier
            .send(io)
            .await
            .map_err(HandleNewClientError::Write)?;
        let mut host_pkt = [0; 256];
        let host_pkt = Packet::wrap(
            &mut host_pkt,
            BlockSize::B8,
            true,
            |buf| {
                crate::message::KeyExchangeInit::new_payload(
                    buf,
                    ALGORITHM_NAMES.into_iter().copied(),
                    [self.host_key.name()].into_iter(),
                    CIPHER_NAMES.into_iter().copied(),
                    CIPHER_NAMES.into_iter().copied(),
                    [].into_iter(),
                    [].into_iter(),
                    [].into_iter(),
                    [].into_iter(),
                    [].into_iter(),
                    [].into_iter(),
                )
                .0
                .len()
            },
            &mut rng,
        );
        io.write_all(host_pkt.as_raw())
            .await
            .map_err(HandleNewClientError::Write)?;

        // Receive id + kexinit
        let mut ident = [0; Identifier::MAX_LEN];
        let client_ident = Identifier::parse(io, &mut ident)
            .await
            .map_err(HandleNewClientError::ParseIdentifierError)?;

        update_string(&mut exchange_hash, client_ident.as_ref());
        update_string(&mut exchange_hash, self.identifier.as_ref());
        let pkt = Packet::parse(io, &mut pkt_buf)
            .await
            .map_err(HandleNewClientError::PacketParseError)?;
        update_string(&mut exchange_hash, pkt.payload());
        update_string(&mut exchange_hash, host_pkt.payload());

        let msg = Message::parse(pkt.payload())
            .map_err(HandleNewClientError::MessageParseError)?
            .into_kex_init()
            .ok_or(HandleNewClientError::ExpectedKeyExchangeInit)?;
        if !msg
            .kex_algorithms()
            .any(|s| ALGORITHM_NAMES.iter().any(|t| t.as_bytes() == s))
            || !msg
                .server_host_key_algorithms()
                .any(|s| s == self.host_key.name().as_bytes())
            || !msg
                .encryption_algorithms_client_to_server()
                .any(|s| CIPHER_NAMES.iter().any(|t| t.as_bytes() == s))
            || !msg
                .encryption_algorithms_server_to_client()
                .any(|s| CIPHER_NAMES.iter().any(|t| t.as_bytes() == s))
        // TODO we should handle the case where a HMAC needs to be selected if we're
        // not using chacha20-poly1305
        {
            return Err(HandleNewClientError::UnsupportedAlgorithms);
        }

        // Generate temporary key for exchanging the secret
        let server_ephermal_secret = x25519_dalek::EphemeralSecret::new(&mut rng);
        let server_ephermal_public = x25519_dalek::PublicKey::from(&server_ephermal_secret);

        // Receive the client's temporary key
        let pkt = Packet::parse(io, &mut pkt_buf)
            .await
            .map_err(HandleNewClientError::PacketParseError)?;
        let client_ephermal_public = Message::parse(pkt.payload())
            .unwrap()
            .into_kex_ecdh_init()
            .unwrap()
            .into_public_key();

        // Compute shared secret
        let (b, _) = KeyExchangeEcdhReply::server_host_key(&mut pkt_buf, &self.host_key.public);
        exchange_hash.update(b);
        update_string(&mut exchange_hash, client_ephermal_public.as_bytes());
        update_string(&mut exchange_hash, server_ephermal_public.as_bytes());
        let shared_secret = server_ephermal_secret.diffie_hellman(&client_ephermal_public);
        update_pos_mpint(&mut exchange_hash, shared_secret.as_bytes());

        let hash = exchange_hash.finalize();
        let sig = self.host_key.secret.sign(&hash);

        let key_material = KeyMaterial::<DKeyMaterial>::new(*shared_secret.as_bytes(), hash.into());

        // send secret
        let pkt = Packet::wrap(
            &mut pkt_buf,
            BlockSize::B8,
            true,
            |buf| {
                KeyExchangeEcdhReply::new_payload(
                    buf,
                    &self.host_key.public,
                    &server_ephermal_public,
                    &sig,
                )
                .0
                .len()
            },
            &mut rng,
        );
        io.write_all(pkt.into_raw(0))
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
            |buf| Message::NewKeys(NewKeys).serialize(buf).unwrap().len(),
            &mut rng,
        );
        io.write_all(pkt.as_raw())
            .await
            .map_err(HandleNewClientError::Write)?;
        let pkt = Packet::parse(io, &mut pkt_buf)
            .await
            .map_err(HandleNewClientError::PacketParseError)?;
        Message::parse(pkt.payload())
            .unwrap()
            .into_new_keys()
            .unwrap();

        Ok(HostClient {
            receive_cipher,
            send_cipher,
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
    Read(io::Error),
    Write(io::Error),
}

pub struct Out<D: Cipher>(D);

impl<D: Cipher> Out<D> {
    pub async fn send<Io, F, Rng>(
        &mut self,
        buf: &mut [u8],
        mut fill: F,
        io: &mut Io,
        rng: Rng,
    ) -> Result<(), OutError>
    where
        Io: io::AsyncWriteExt + Unpin,
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
    pub async fn recv<'a, Io>(
        &mut self,
        buf: &'a mut [u8],
        io: &mut Io,
    ) -> Result<&'a mut [u8], InError>
    where
        Io: io::AsyncReadExt + Unpin,
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
}

impl<D: Cipher> HostClient<D> {
    pub fn send_receive(&mut self) -> (&mut Out<D>, &mut In<D>) {
        (&mut self.send_cipher, &mut self.receive_cipher)
    }
}

impl SignKey for p256::NistP256 {
    fn name() -> &'static str {
        "ecdsa-sha2-nistp256"
    }
}
