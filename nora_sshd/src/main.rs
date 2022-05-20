use async_std::{net::{TcpListener, TcpStream}, process};
use rand::{rngs::StdRng, SeedableRng, CryptoRng, RngCore};
use futures::{
    future::{FusedFuture, FutureExt},
    io::{AsyncRead, AsyncWrite},
    pin_mut, select,
    stream::{FuturesUnordered, StreamExt},
    stream_select,
};
use nora_ssh::{
    cipher::Cipher,
    host::{Host, HostClient},
    identifier::Identifier,
    message::{
        channel::{self, Data, Failure, OpenConfirmation},
        userauth::Success,
        Channel, Message, ServiceAccept, UserAuth,
    },
};

#[async_std::main]
async fn main() {
    use rand::SeedableRng;
    let mut rng = rand::rngs::StdRng::seed_from_u64(0);
    let server_secret = ecdsa::SigningKey::<p256::NistP256>::random(&mut rng);

    let l = TcpListener::bind("127.0.0.1:2222").await.unwrap();
    let server = Host::new(
        Identifier::new(b"SSH-2.0-nora_ssh example").unwrap(),
        server_secret,
    );

    let mut new_clients = FuturesUnordered::new();
    let mut clients = FuturesUnordered::new();

    loop {
        select! {
            c = l.accept().fuse() => {
                new_clients.push(handle_new_client(&server, c.unwrap().0));
            },
            (rng, io, client) = new_clients.select_next_some() => {
                clients.push(handle_client(rng, io, client));
            }
            _ = clients.next() => {}
        };
    }
}

async fn handle_new_client<'a, Io: AsyncRead + AsyncWrite + Unpin> (
    server: &'a Host<p256::NistP256>,
    mut io: Io,
) -> (impl CryptoRng + RngCore, Io, HostClient<impl Cipher>) {
    let mut rng = rand::rngs::StdRng::from_entropy();
    let c = &mut io;
    let mut hc = server.handle_new_client(c, &mut rng).await.unwrap();
    let (send, recv) = hc.send_receive();
    let mut pkt_buf = [0; 35000];
    let mut pkt_buf_mini = [0; 64];

    // Wait for userauth
    let data = recv.recv(&mut pkt_buf, c).await.unwrap();
    let msg = Message::parse(data).unwrap();
    let srv = <&[u8]>::from(msg.into_service_request().unwrap());
    match srv {
        b"ssh-userauth" => {
            let msg = Message::ServiceAccept(ServiceAccept::new(srv));
            send.send(
                &mut pkt_buf_mini,
                |buf| msg.serialize(buf).unwrap().len(),
                c,
                &mut rng,
            )
            .await
            .unwrap();
        }
        _ => todo!(),
    }

    // Wait for userauth request
    let data = recv.recv(&mut pkt_buf, c).await.unwrap();
    let msg = Message::parse(data).unwrap();
    let ua = msg.into_user_auth().unwrap().into_request().unwrap();
    dbg!(core::str::from_utf8(ua.user));
    dbg!(core::str::from_utf8(ua.service));
    dbg!(core::str::from_utf8(ua.method));

    // Just accept lol
    let msg = Message::UserAuth(UserAuth::Success(Success));
    send.send(
        &mut pkt_buf,
        |buf| msg.serialize(buf).unwrap().len(),
        c,
        &mut rng,
    )
    .await
    .unwrap();

    // Open channel
    let data = recv.recv(&mut pkt_buf, c).await.unwrap();
    let msg = Message::parse(data).unwrap();
    let ua = msg.into_channel().unwrap().into_open().unwrap();
    dbg!(core::str::from_utf8(ua.ty));
    dbg!(ua.channel_a);
    dbg!(ua.window_size);
    dbg!(ua.max_packet_size);

    // Accept channel
    let msg = Message::Channel(Channel::OpenConfirmation(OpenConfirmation {
        channel_a: ua.channel_a,
        channel_b: 0xdeadbeef,
        window_size: ua.window_size,
        max_packet_size: ua.max_packet_size,
        stuff: &[],
    }));
    send.send(
        &mut pkt_buf,
        |buf| msg.serialize(buf).unwrap().len(),
        c,
        &mut rng,
    )
    .await
    .unwrap();

    // Send data
    let msg = Message::Channel(Channel::Data(Data {
        channel_b: 0,
        data: b"Hello, world!\n",
    }));
    send.send(
        &mut pkt_buf,
        |buf| msg.serialize(buf).unwrap().len(),
        c,
        &mut rng,
    )
    .await
    .unwrap();
    (rng, io, hc)
}

async fn handle_client(
    mut rng: impl CryptoRng + RngCore,
    mut io: impl AsyncRead + AsyncWrite + Unpin,
    mut client: HostClient<impl Cipher>,
) {
    let mut pkt_buf = [0; 35000];
    let c = &mut io;
    let (send, recv) = client.send_receive();

    // Receive data
    loop {
        let data = match recv.recv(&mut pkt_buf, c).await {
            Ok(d) => d,
            Err(_) => break,
        };
        match Message::parse(data).unwrap() {
            Message::Channel(Channel::Request(r)) => {
                dbg!(r.channel_b);
                dbg!(core::str::from_utf8(r.ty));
                dbg!(r.want_reply);
                if r.want_reply {
                    let msg = if r.ty == b"shell" {
                        // Accept request
                        Message::Channel(Channel::Success(channel::Success { channel_a: 0 }))
                    } else {
                        // Reject request
                        Message::Channel(Channel::Failure(Failure { channel_a: 0 }))
                    };
                    send.send(
                        &mut pkt_buf,
                        |buf| msg.serialize(buf).unwrap().len(),
                        c,
                        &mut rng,
                    )
                    .await
                    .unwrap();
                }
            }
            Message::Channel(Channel::Data(d)) => {
                dbg!(d.channel_b);
                dbg!(core::str::from_utf8(d.data));
            }
            Message::Channel(Channel::Eof(e)) => {
                dbg!(e.channel_a);
                break;
            }
            Message::Disconnect(d) => {
                dbg!(d.reason);
                dbg!(core::str::from_utf8(d.description));
                dbg!(core::str::from_utf8(d.language));
                break;
            }
            _ => todo!(),
        }
    }
}
