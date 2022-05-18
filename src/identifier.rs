#[derive(Clone, Copy)]
pub struct Identifier<'a>(&'a [u8]);

impl<'a> Identifier<'a> {
    pub const MAX_LEN: usize = 255 - b"\r\n".len();

    pub fn new(ident: &'a [u8]) -> Option<Self> {
        (ident.len() <= Self::MAX_LEN).then(|| Self(ident))
    }

    pub fn parse<R, F>(mut read: F, buf: &'a mut [u8; 253]) -> Result<Self, ParseIdentError<R>>
    where
        F: FnMut(&mut [u8]) -> Result<(), R>,
    {
        let mut read = || {
            let mut b = [0];
            read(&mut b).map(|()| b[0]).map_err(ParseIdentError::Other)
        };
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
            state = match (state, read()?) {
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

    pub fn send<R, F>(self, mut send: F) -> Result<(), R>
    where
        F: FnMut(&[u8]) -> Result<(), R>,
    {
        send(self.0)?;
        send(b"\r\n")
    }
}

impl AsRef<[u8]> for Identifier<'_> {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

#[derive(Debug)]
pub enum ParseIdentError<R> {
    IdentifierTooLong,
    IncompatibleProtocol,
    Other(R),
}
