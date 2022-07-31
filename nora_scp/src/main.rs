//! Implementation of SCP1, i.e. the original SCP.
//!
//! I couldn't find any documentation about it but monitoring traffic it seems to be
//! a very simple protocol:
//!
//! 1) The sender waits for the receiver to send a `\0`.
//! 2) The sender sends a header (filename, metadata, ...) for each file.
//! 3) The receiver responds with `\0`.
//! 4) The sender sends the full contents of the file and `\0`.
//! 5) The receiver responds with `\0`.
//! 6) Repeat from 2) for every file. When done, the sender simply closes the channel.
//!
//! The header is formatted as `C0rwx size filename\n`, where `rwx` are the file permissions
//! in octal and `size` is the size of the file in decimals.
//!
//! For directories the header is formatted as `D0rwx size dirname\n`.

use std::{
    cell::RefCell,
    env,
    error::Error,
    fs::{self, File},
    io::{self, BufRead, BufReader, Read, Write},
    path::PathBuf,
    str,
};

fn main() {
    match start() {
        Ok(()) => {}
        Err(e) => eprintln!("{}", e),
    }
}

fn start() -> Result<(), Box<dyn Error>> {
    enum Mode {
        Client,
        Send,
        Receive,
    }
    let mut mode = Mode::Client;
    let mut make_dir = false;
    let mut args = std::env::args_os().skip(1);
    let mut paths = Vec::new();
    while let Some(a) = args.next() {
        match a.to_str() {
            Some("-d") => make_dir = true,
            Some("-f") => mode = Mode::Send,
            Some("-t") => mode = Mode::Receive,
            Some(f) if f.starts_with("-") => Err(format!("invalid flag {:?}", f))?,
            _ => paths.push(a.into()),
        }
    }

    match mode {
        Mode::Receive => receive(&paths, make_dir),
        Mode::Send => send(&paths),
        Mode::Client => todo!(),
    }
}

fn receive(to: &[PathBuf], make_dir: bool) -> Result<(), Box<dyn Error>> {
    let stdin = RefCell::new(BufReader::new(io::stdin().lock()));
    let stdout = RefCell::new(io::stdout().lock());
    let ping_ready = || {
        stdout.borrow_mut().write_all(b"\0")?;
        stdout.borrow_mut().flush()
    };

    let mut buf = [0; 1 << 15];
    let mut header = Vec::from([0]);

    enum Type {
        File,
    }

    fn read_header<'a, R: BufRead>(
        stdin: &RefCell<R>,
        header: &'a mut Vec<u8>,
    ) -> Result<Option<(Type, &'a str, usize, &'a str)>, Box<dyn Error>> {
        header.resize(1, 0);
        let n = stdin.borrow_mut().read(&mut header[..1])?;
        match (n, header[0]) {
            (0, _) => Ok(None),
            (_, b'C') => {
                stdin.borrow_mut().read_until(b'\n', header)?;
                // TODO try to support non-UTF8 when possible.
                let header = str::from_utf8(header)?;
                let mut parts = header.split(' ');
                let mode = parts.next().ok_or("missing mode")?;
                let size = parts.next().ok_or("missing size")?;
                let mut file = parts.next().ok_or("missing file")?;
                if file.bytes().last() == Some(b'\n') {
                    file = &file[..file.len() - 1];
                }
                // TODO check for garbage
                let size = size.parse::<usize>()?;
                Ok(Some((Type::File, mode, size, file)))
            }
            (_, b'D') => todo!(),
            c => Err(format!("invalid mode {:?}", c))?,
        }
    };

    let mut transfer_file = |mut f: File, mut size: usize| -> Result<_, Box<dyn Error>> {
        while size > 0 {
            let l = size.min(buf.len());
            stdin.borrow_mut().read_exact(&mut buf[..l])?;
            f.write_all(&mut buf[..l])?;
            size -= l;
        }
        // Read ack
        stdin.borrow_mut().read_exact(&mut buf[..1])?;
        if buf[0] != b'\0' {
            Err("expected '\\0'")?;
        }
        ping_ready()?;
        Ok(())
    };

    if make_dir {
        let dir = match to {
            [d] => d,
            _ => Err("expected exactly one path")?,
        };
        fs::create_dir_all(dir)?;
        env::set_current_dir(dir)?;
        ping_ready()?;
        // TODO actually do something with mode.
        while let Some((ty, _mode, size, file)) = read_header(&stdin, &mut header)? {
            match ty {
                Type::File => {
                    let f = File::create(file)?;
                    ping_ready()?;
                    transfer_file(f, size)?;
                }
            }
        }
    } else {
        ping_ready()?;
        for path in to {
            let (ty, _mode, size, _file) =
                read_header(&stdin, &mut header)?.ok_or("expected file")?;
            match ty {
                Type::File => {
                    // TODO actually do something with mode.
                    if let Some(dirs) = path.parent() {
                        fs::create_dir_all(dirs)?;
                    }
                    let f = File::create(path)?;
                    ping_ready()?;
                    transfer_file(f, size)?;
                }
            }
        }
    }
    Ok(())
}

fn send(from: &[PathBuf]) -> Result<(), Box<dyn Error>> {
    let mut buf = [0; 1 << 15];
    for path in from {
        let mut f = File::open(path)?;
        // TODO try to support non-UTF8 when possible.
        let name = path
            .file_name()
            .unwrap()
            .to_str()
            .ok_or("failed to convert path to UTF-8")?;
        println!("C{:04o} {} {}", 0o644, 42, name);
        let mut out = io::stdout().lock();
        loop {
            match f.read(&mut buf)? {
                0 => break,
                n => out.write_all(&buf[..n])?,
            }
        }
    }
    Ok(())
}
