#![deny(unsafe_code)]

use async_std::{
    net::{TcpListener, TcpStream},
    process,
};
use futures::io::{AsyncReadExt, ReadHalf, WriteHalf};
use nora_ssh::{
    auth::Auth,
    cipher,
    server::{IoSet, Server, ServerHandlers, SpawnType},
    Identifier,
};
use rand::rngs::StdRng;
use std::os::unix::ffi::OsStrExt;

#[async_std::main]
async fn main() -> ! {
    use rand::SeedableRng;
    let mut rng = rand::rngs::StdRng::seed_from_u64(0);
    let server_secret = ecdsa::SigningKey::<p256::NistP256>::random(&mut rng);

    let listener = TcpListener::bind("127.0.0.1:2222").await.unwrap();
    let server = Server::new(
        Identifier::new(b"SSH-2.0-nora_ssh example").unwrap(),
        server_secret,
        Handlers { listener },
    );

    server.start().await
}

struct Handlers {
    listener: TcpListener,
}

struct User {
    _name: Box<str>,
    shell: Option<process::Child>,
}

#[async_trait::async_trait]
impl ServerHandlers for Handlers {
    type Sign = p256::NistP256;
    type Crypt = cipher::ChaCha20Poly1305;
    type Read = ReadHalf<TcpStream>;
    type Write = WriteHalf<TcpStream>;
    type User = User;
    type Stdin = process::ChildStdin;
    type Stdout = process::ChildStdout;
    type Stderr = process::ChildStderr;
    type Rng = StdRng;

    async fn accept(&self) -> (Self::Read, Self::Write) {
        self.listener.accept().await.unwrap().0.split()
    }

    async fn public_key_exists<'a>(
        &self,
        _user: &'a [u8],
        _service: &'a [u8],
        algorithm: &'a [u8],
        _key: &'a [u8],
    ) -> Result<(), ()> {
        if algorithm == b"ssh-ed25519" {
            Ok(())
        } else {
            Err(())
        }
    }

    async fn authenticate<'a>(
        &self,
        user: &'a [u8],
        _service: &'a [u8],
        auth: Auth<'a>,
    ) -> Result<Self::User, ()> {
        match auth {
            Auth::None => Err(()),
            Auth::Password(_pwd) => {
                todo!()
            }
            Auth::PublicKey {
                algorithm,
                key,
                signature,
                message,
            } => {
                if algorithm != b"ssh-ed25519" {
                    return Err(());
                }
                use ed25519_dalek::Verifier;
                // FIXME don't fucking just reuse key doofus.
                let key = ed25519_dalek::PublicKey::from_bytes(key.try_into().map_err(|_| ())?)
                    .map_err(|_| ())?;
                key.verify(message, &signature.try_into().map_err(|_| ())?)
                    .map_err(|_| ())?;
                Ok(User {
                    _name: core::str::from_utf8(user).unwrap().into(),
                    shell: None,
                })
            }
        }
    }

    async fn spawn<'a>(
        &self,
        user: &'a mut Self::User,
        ty: SpawnType<'a>,
        _data: &'a [u8],
    ) -> Result<IoSet<Self::Stdin, Self::Stdout, Self::Stderr>, ()> {
        let wait = |child: &mut process::Child| {
            let wait = child.status();
            async move { wait.await.unwrap().code().unwrap_or(0) as u32 }
        };
        match ty {
            SpawnType::Shell => {
                let shell = std::env::var_os("SHELL").unwrap();
                let mut shell = process::Command::new(shell)
                    .stdin(process::Stdio::piped())
                    .stdout(process::Stdio::piped())
                    .stderr(process::Stdio::piped())
                    .spawn()
                    .unwrap();
                let io = IoSet {
                    stdin: shell.stdin.take(),
                    stdout: shell.stdout.take(),
                    stderr: shell.stderr.take(),
                    wait: Box::pin(wait(&mut shell)),
                };
                user.shell = Some(shell);
                Ok(io)
            }
            SpawnType::Exec { command } => {
                let mut args = command
                    .split(|c| c.is_ascii_whitespace())
                    .filter(|s| !s.is_empty())
                    .map(std::ffi::OsStr::from_bytes);
                let bin = args.next().unwrap();
                let mut shell = process::Command::new(bin)
                    .stdin(process::Stdio::piped())
                    .stdout(process::Stdio::piped())
                    .stderr(process::Stdio::piped())
                    .args(args)
                    .spawn()
                    .unwrap();
                let io = IoSet {
                    stdin: shell.stdin.take(),
                    stdout: shell.stdout.take(),
                    stderr: shell.stderr.take(),
                    wait: Box::pin(wait(&mut shell)),
                };
                user.shell = Some(shell);
                Ok(io)
            }
        }
    }
}
