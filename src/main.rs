use std::io::{Read, Write};
use std::net::TcpListener;

fn main() {
    use nora_ssh::{host::Host, identifier::Identifier};
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
        let mut pkt = [0; 35000];
        let pkt = recv.recv(&mut pkt, |d| c.read_exact(d)).unwrap();
        dbg!(pkt.payload());
    }
}
