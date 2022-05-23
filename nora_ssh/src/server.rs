use crate::{
    arena::Arena,
    cipher::Cipher,
    host::{self, Host, HostClient, HostKey, InError, OutError, SignKey},
    identifier::Identifier,
    message::{self as msg, Message},
    packet::Packet,
    sync::LocalMutex,
    Handler,
};
use core::{cell::RefCell, future::Future, pin::Pin};
use ecdsa::{hazmat::SignPrimitive, SignatureSize};
use elliptic_curve::{
    ops::{Invert, Reduce},
    Curve, Scalar,
};
use futures::{
    io, select,
    stream::{FusedStream, FuturesUnordered},
    AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, FutureExt, Stream, StreamExt,
};
use generic_array::ArrayLength;
use rand::{CryptoRng, RngCore, SeedableRng};
use std::rc::Rc;
use subtle::CtOption;

type Authenticating<Handlers> = Pin<Box<dyn Future<Output = Result<Client<Handlers>, ()>>>>;
type Reading = Pin<Box<dyn Future<Output = Result<(), ReceiveError>>>>;

pub struct Server<Handlers>
where
    Handlers: ServerHandlers,
    Scalar<Handlers::Sign>: Invert<Output = CtOption<Scalar<Handlers::Sign>>>
        + Reduce<<Handlers::Sign as Curve>::UInt>
        + SignPrimitive<Handlers::Sign>,
    SignatureSize<Handlers::Sign>: ArrayLength<u8>,
{
    host: Host<Handlers::Sign>,
    handlers: Handlers,
}

impl<Handlers> Server<Handlers>
where
    Handlers: ServerHandlers,
    Scalar<Handlers::Sign>: Invert<Output = CtOption<Scalar<Handlers::Sign>>>
        + Reduce<<Handlers::Sign as Curve>::UInt>
        + SignPrimitive<Handlers::Sign>,
    SignatureSize<Handlers::Sign>: ArrayLength<u8>,
{
    pub fn new(
        identifier: Identifier<'static>,
        key: impl Into<HostKey<Handlers::Sign>>,
        handlers: Handlers,
    ) -> Self {
        Self {
            host: Host::new(identifier, key),
            handlers,
        }
    }
}

impl<Handlers> Server<Handlers>
where
    Handlers: ServerHandlers<Sign = p256::NistP256, Crypt = crate::cipher::ChaCha20Poly1305>,
{
    pub async fn start(self) -> ! {
        let mut new_clients = FuturesUnordered::new();
        let mut clients = FuturesUnordered::new();
        loop {
            select! {
                (rd, wr) = self.handlers.accept().fuse() => {
                    new_clients.push(self.authenticate_new_client(rd, wr));
                },
                cl = new_clients.select_next_some() => {
                    if let Ok(cl) = cl {
                        clients.push(cl.start(&self))
                    }
                },
                _ = clients.select_next_some() => {},
            };
        }
    }

    async fn authenticate_new_client(
        &self,
        mut rd: Handlers::Read,
        mut wr: Handlers::Write,
    ) -> Result<Client<Handlers>, ()> {
        let mut rng = <Handlers::Rng as SeedableRng>::from_entropy();

        // Exchange keys
        let client = self
            .host
            .handle_new_client(&mut rd, &mut wr, &mut rng)
            .await
            .map_err(|_| ())?;
        let (mut wr_enc, mut rd_enc) = client.into_send_receive();

        let mut pkt_buf = [0; 35000];
        let mut pkt_buf_mini = [0; 256];

        // Wait for userauth
        let data = rd_enc.recv(&mut pkt_buf, &mut rd).await.unwrap();
        let msg = Message::parse(data).unwrap();
        let srv = <&[u8]>::from(msg.into_service_request().unwrap());
        match srv {
            b"ssh-userauth" => {
                let msg = Message::ServiceAccept(msg::ServiceAccept::new(srv));
                wr_enc
                    .send(
                        &mut pkt_buf_mini,
                        |buf| msg.serialize(buf).unwrap().len(),
                        &mut wr,
                        &mut rng,
                    )
                    .await
                    .unwrap();
            }
            _ => todo!(),
        }

        // Wait for userauth request
        let data = rd_enc.recv(&mut pkt_buf, &mut rd).await.unwrap();
        let msg = Message::parse(data).unwrap();
        let ua = msg.into_user_auth().unwrap().into_request().unwrap();

        // Attempt authentication
        loop {
            match self.handlers.authenticate(b"TODO").await {
                Ok(user) => {
                    // Accept
                    let msg = Message::UserAuth(msg::UserAuth::Success(msg::userauth::Success));
                    wr_enc
                        .send(
                            &mut pkt_buf,
                            |buf| msg.serialize(buf).unwrap().len(),
                            &mut wr,
                            &mut rng,
                        )
                        .await
                        .unwrap();
                    return Ok(Client {
                        read: RefCell::new((rd, rd_enc)),
                        write: LocalMutex::new((wr, wr_enc)),
                        user: RefCell::new(user),
                        channels: RefCell::new(Arena::new()),
                        rng: RefCell::new(rng),
                    });
                }
                Err(()) => break, // TODO
            }
        }
        Err(())
    }
}

struct Client<Handlers>
where
    Handlers: ServerHandlers,
    Scalar<Handlers::Sign>: Invert<Output = CtOption<Scalar<Handlers::Sign>>>
        + Reduce<<Handlers::Sign as Curve>::UInt>
        + SignPrimitive<Handlers::Sign>,
    SignatureSize<Handlers::Sign>: ArrayLength<u8>,
{
    read: RefCell<(Handlers::Read, host::In<Handlers::Crypt>)>,
    write: LocalMutex<(Handlers::Write, host::Out<Handlers::Crypt>)>,
    user: RefCell<Handlers::User>,
    channels: RefCell<Arena<Channel<Handlers::Stdin>>>,
    rng: RefCell<Handlers::Rng>,
}

impl<Handlers> Client<Handlers>
where
    Handlers: ServerHandlers,
    Scalar<Handlers::Sign>: Invert<Output = CtOption<Scalar<Handlers::Sign>>>
        + Reduce<<Handlers::Sign as Curve>::UInt>
        + SignPrimitive<Handlers::Sign>,
    SignatureSize<Handlers::Sign>: ArrayLength<u8>,
{
    async fn send<F>(&self, buf: &mut [u8], fill: F) -> Result<(), OutError>
    where
        F: FnOnce(&mut [u8]) -> usize,
    {
        let mut l = self.write.lock().await;
        let (wr, enc) = &mut *l;
        enc.send(buf, fill, wr, &mut *self.rng.borrow_mut()).await
    }

    async fn send_channel(
        &self,
        buf: &mut [u8],
        channel: u32,
        data: &[u8],
    ) -> Result<(), OutError> {
        let msg = Message::Channel(msg::Channel::Data(msg::channel::Data {
            recipient_channel: channel,
            data,
        }));
        self.send(buf, |buf| msg.serialize(buf).unwrap().len())
            .await
    }

    async fn start(self, server: &Server<Handlers>) -> Result<(), ReceiveError> {
        let mut stdout_inputs = FuturesUnordered::new();
        let mut stderr_inputs = FuturesUnordered::new();
        async fn read<Io: AsyncRead + Unpin>(
            mut io: Io,
            channel: u32,
        ) -> (Io, [u8; 256], usize, u32) {
            let mut buf = [0; 256];
            let l = io.read(&mut buf).await.unwrap();
            (io, buf, l, channel)
        }
        let mut buf = [0; 35000];
        loop {
            select! {
                ret = self.receive(&mut buf, server).fuse() => match ret {
                    Ok(Action::Exit) => return Ok(()),
                    Ok(Action::NewIo { stdout, stderr, channel }) => {
                        if let Some(stdout) = stdout {
                            dbg!();
                            stdout_inputs.push(read(stdout, channel));
                        }
                        if let Some(stderr) = stderr {
                            dbg!();
                            stderr_inputs.push(read(stderr, channel));
                        }
                    }
                    Err(e) => return Err(e),
                },
                (stdout, data, l, channel) = stdout_inputs.select_next_some() => {
                    stdout_inputs.push(read(stdout, channel));
                    self.send_channel(&mut buf, channel, &data[..l]).await;
                },
                (stderr, data, l, channel) = stderr_inputs.select_next_some() => {
                    stderr_inputs.push(read(stderr, channel));
                    self.send_channel(&mut buf, channel, &data[..l]).await;
                },
            }
        }
    }

    async fn receive(
        &self,
        buf: &mut [u8],
        server: &Server<Handlers>,
    ) -> Result<Action<Handlers::Stdout, Handlers::Stderr>, ReceiveError> {
        let mut read = self.read.borrow_mut();
        let (rd, enc) = &mut *read;
        loop {
            let data = enc.recv(buf, rd).await.map_err(ReceiveError::In)?;
            match Message::parse(data).unwrap() {
                Message::Channel(msg::Channel::Open(o)) => {
                    let ch = self.channels.borrow_mut().insert(Channel {
                        peer_channel: o.sender_channel,
                        ty: ChannelType::Session, // TODO actually check
                        stdin: None,
                    });
                    let msg = Message::Channel(msg::Channel::OpenConfirmation(
                        msg::channel::OpenConfirmation {
                            sender_channel: ch,
                            recipient_channel: o.sender_channel,
                            window_size: o.window_size,
                            max_packet_size: o.max_packet_size,
                            stuff: &[],
                        },
                    ));
                    self.send(buf, |buf| msg.serialize(buf).unwrap().len())
                        .await
                        .map_err(ReceiveError::Out)?;
                }
                Message::Channel(msg::Channel::Request(r)) => {
                    let mut channels = self.channels.borrow_mut();
                    let ch = channels.get_mut(r.recipient_channel).unwrap();
                    let (msg, stdout, stderr) = match r.ty {
                        b"shell" => {
                            let io = server
                                .handlers
                                .spawn(&mut *self.user.borrow_mut(), SpawnType::Shell, &[])
                                .await
                                .unwrap();
                            ch.stdin = io.stdin;
                            (
                                Message::Channel(msg::Channel::Success(msg::channel::Success {
                                    recipient_channel: ch.peer_channel,
                                })),
                                io.stdout,
                                io.stderr,
                            )
                        }
                        _ => (
                            Message::Channel(msg::Channel::Failure(msg::channel::Failure {
                                recipient_channel: ch.peer_channel,
                            })),
                            None,
                            None,
                        ),
                    };
                    let channel = ch.peer_channel;
                    drop(channels);
                    if r.want_reply {
                        self.send(buf, |buf| msg.serialize(buf).unwrap().len())
                            .await
                            .map_err(ReceiveError::Out)?;
                    }
                    match (stdout, stderr) {
                        (None, None) => {}
                        (stdout, stderr) => {
                            return Ok(Action::NewIo {
                                stdout,
                                stderr,
                                channel,
                            })
                        }
                    }
                }
                Message::Channel(msg::Channel::Data(d)) => {
                    let mut channels = self.channels.borrow_mut();
                    let ch = channels
                        .get_mut(d.recipient_channel)
                        .unwrap();
                    ch.stdin.as_mut().unwrap().write(d.data).await.unwrap();
                }
                Message::Channel(msg::Channel::Eof(e)) => {
                    self.channels.borrow_mut().remove(e.recipient_channel);
                }
                Message::Channel(msg::Channel::OpenConfirmation(_)) => todo!(),
                Message::Channel(msg::Channel::Success(_)) => todo!(),
                Message::Channel(msg::Channel::Failure(_)) => todo!(),
                Message::Disconnect(_) => return Ok(Action::Exit),
                Message::KeyExchangeInit(_) => todo!(),
                Message::KeyExchangeEcdhInit(_) => todo!(),
                Message::NewKeys(_) => todo!(),
                Message::ServiceRequest(req) => {
                    dbg!(core::str::from_utf8(req.into()));
                    todo!();
                }
                Message::ServiceAccept(_) => todo!(),
                Message::UserAuth(_) => todo!(),
            }
        }
    }
}

enum Action<Stdout, Stderr>
where
    Stdout: AsyncRead + Unpin,
    Stderr: AsyncRead + Unpin,
{
    Exit,
    NewIo {
        stdout: Option<Stdout>,
        stderr: Option<Stderr>,
        channel: u32,
    },
}

pub struct Channel<Stdin>
where
    Stdin: AsyncWrite + Unpin,
{
    peer_channel: u32,
    ty: ChannelType,
    stdin: Option<Stdin>,
}

pub struct IoSet<Stdin, Stdout, Stderr>
where
    Stdin: AsyncWrite + Unpin,
    Stdout: AsyncRead + Unpin,
    Stderr: AsyncRead + Unpin,
{
    pub stdin: Option<Stdin>,
    pub stdout: Option<Stdout>,
    pub stderr: Option<Stderr>,
}

pub enum ChannelType {
    Session,
}

pub enum SpawnType {
    Shell,
}

#[derive(Debug)]
pub enum ReceiveError {
    In(InError),
    Out(OutError),
    Io(io::Error),
}

#[async_trait::async_trait]
pub trait ServerHandlers
where
    Self: 'static,
    Scalar<Self::Sign>: Invert<Output = CtOption<Scalar<Self::Sign>>>
        + Reduce<<Self::Sign as Curve>::UInt>
        + SignPrimitive<Self::Sign>,
    SignatureSize<Self::Sign>: ArrayLength<u8>,
{
    type Sign: SignKey;
    type Crypt: Cipher;
    type Read: AsyncRead + Unpin + 'static;
    type Write: AsyncWrite + Unpin + 'static;
    type User;
    type Stdin: AsyncWrite + Unpin;
    type Stdout: AsyncRead + Unpin;
    type Stderr: AsyncRead + Unpin;
    type Rng: RngCore + CryptoRng + SeedableRng;

    async fn accept(&self) -> (Self::Read, Self::Write);
    async fn authenticate<'a>(&self, data: &'a [u8]) -> Result<Self::User, ()>;
    async fn spawn<'a>(
        &self,
        user: &'a mut Self::User,
        ty: SpawnType,
        data: &'a [u8],
    ) -> Result<IoSet<Self::Stdin, Self::Stdout, Self::Stderr>, ()>;
}