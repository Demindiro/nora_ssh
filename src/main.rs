use std::io::{Read, Write};
use std::net::TcpListener;

fn main() {
    use nora_ssh::{
        host::Host,
        identifier::Identifier,
        message::{
            channel::{self, Data, Failure, OpenConfirmation}, userauth::Success, Channel, Message, ServiceAccept, UserAuth,
        },
    };
    use rand::SeedableRng;
    let mut rng = rand::rngs::StdRng::seed_from_u64(0);
    let server_secret = ecdsa::SigningKey::<p256::NistP256>::random(&mut rng);

    let l = TcpListener::bind("127.0.0.1:2222").unwrap();
    let server = Host::new(
        Identifier::new(b"SSH-2.0-nora_ssh example").unwrap(),
        server_secret,
    );

    for c in l.incoming().map(Result::unwrap) {
        let c = core::cell::RefCell::new(c);
        let mut hc = server
            .handle_new_client(
                |b| c.borrow_mut().read_exact(b),
                |b| c.borrow_mut().write_all(b),
                &mut rng,
            )
            .unwrap();
        let mut c = c.into_inner();
        let (send, recv) = hc.send_receive();
        let mut pkt_buf = [0; 35000];
        let mut pkt_buf_mini = [0; 64];

        // Wait for userauth
        let data = recv.recv(&mut pkt_buf, |d| c.read_exact(d)).unwrap();
        let msg = Message::parse(data).unwrap();
        let srv = <&[u8]>::from(msg.into_service_request().unwrap());
        match srv {
            b"ssh-userauth" => {
                let msg = Message::ServiceAccept(ServiceAccept::new(srv));
                send.send(
                    &mut pkt_buf_mini,
                    |buf| msg.serialize(buf).unwrap().len(),
                    |d| c.write_all(d),
                    &mut rng,
                )
                .unwrap();
            }
            _ => todo!(),
        }

        // Wait for userauth request
        let data = recv.recv(&mut pkt_buf, |d| c.read_exact(d)).unwrap();
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
            |d| c.write_all(d),
            &mut rng,
        )
        .unwrap();

        // Open channel
        let data = recv.recv(&mut pkt_buf, |d| c.read_exact(d)).unwrap();
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
            |d| c.write_all(d),
            &mut rng,
        )
        .unwrap();

        // Send data
        let msg = Message::Channel(Channel::Data(Data {
            channel_b: 0,
            data: b"Hello, world!\n",
        }));
        send.send(
            &mut pkt_buf,
            |buf| msg.serialize(buf).unwrap().len(),
            |d| c.write_all(d),
            &mut rng,
        )
        .unwrap();

        // Receive data
        loop {
            let data = match recv.recv(&mut pkt_buf, |d| c.read_exact(d)) {
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
                            Message::Channel(Channel::Success(channel::Success {
                                channel_a: 0,
                            }))
                        } else {
                            // Reject request
                            Message::Channel(Channel::Failure(Failure {
                                channel_a: 0,
                            }))
                        };
                        send.send(
                            &mut pkt_buf,
                            |buf| msg.serialize(buf).unwrap().len(),
                            |d| c.write_all(d),
                            &mut rng,
                        )
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
}
