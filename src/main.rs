use std::io::{Read, Write};
use std::net::TcpListener;

fn main() {
    use nora_ssh::{
        host::Host,
        identifier::Identifier,
        message::{userauth::Success, Message, ServiceAccept, UserAuth},
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
    }
}
