use core::slice;

#[derive(Clone, Copy)]
pub struct Identifier<'a>(&'a [u8]);

impl<'a> Identifier<'a> {
    pub const MAX_LEN: usize = 255 - b"\r\n".len();

    pub fn new(ident: &'a [u8]) -> Option<Self> {
        (ident.len() <= Self::MAX_LEN).then(|| Self(ident))
    }

    // We can't use Self because the compiler is retarded.
    pub async fn parse<Io>(
        io: &mut Io,
        buf: &'a mut [u8; 253],
    ) -> Result<Identifier<'a>, ParseIdentError>
    where
        Io: io::AsyncReadExt + Unpin,
    {
        // SSH-protoversion-softwareversion SP comments CR LF
        // protocol version MUST be "2.0"

        // Ignore any lines that don't start with "SSH-"
        enum State {
            S,
            SS,
            SSH,
            Ignore,
            EolCr,
            EolLf,
        }
        let mut state = State::EolLf;
        loop {
            let mut b = 0;
            io.read_exact(slice::from_mut(&mut b))
                .await
                .map_err(ParseIdentError::Io)?;
            state = match (state, b) {
                (State::EolLf, b'S') => State::S,
                (State::S, b'S') => State::SS,
                (State::SS, b'S') => State::SS,
                (State::SS, b'H') => State::SSH,
                (State::SSH, b'-') => break,
                (State::Ignore, b'\r') => State::EolCr,
                (State::EolCr, b'\n') => State::EolLf,
                _ => State::Ignore,
            };
        }

        // Match "2.0" as protocol
        let mut b = [0; 4];
        io.read_exact(&mut b).await.map_err(ParseIdentError::Io)?;
        match b {
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
            let mut b = 0;
            io.read_exact(slice::from_mut(&mut b))
                .await
                .map_err(ParseIdentError::Io)?;
            got_cr = match (got_cr, b) {
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

    pub async fn send<Io>(self, io: &mut Io) -> Result<(), io::Error>
    where
        Io: io::AsyncWriteExt + Unpin,
    {
        io.write_all(self.0).await?;
        io.write_all(b"\r\n").await
    }
}

impl AsRef<[u8]> for Identifier<'_> {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

#[derive(Debug)]
pub enum ParseIdentError {
    IdentifierTooLong,
    IncompatibleProtocol,
    Io(io::Error),
}
