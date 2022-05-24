use core::slice;
use futures::io;
use nora_ssh_core::identifier::Identifier;

pub async fn parse<'a, 'b: 'a, Io>(
    io: &'b mut Io,
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

    Identifier::new(&buf[..i]).ok_or(ParseIdentError::IdentifierTooLong)
}

pub async fn send<Io>(id: Identifier<'_>, io: &mut Io) -> Result<(), io::Error>
where
    Io: io::AsyncWriteExt + Unpin,
{
    io.write_all(id.as_ref()).await?;
    io.write_all(b"\r\n").await
}

#[derive(Debug)]
pub enum ParseIdentError {
    IdentifierTooLong,
    IncompatibleProtocol,
    Io(io::Error),
}
