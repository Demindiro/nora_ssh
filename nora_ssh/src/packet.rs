use futures::io::{self, AsyncReadExt};
use nora_ssh_core::packet::{BlockSize, Packet, WrapRawError};

pub async fn parse<'a, Io: AsyncReadExt + Unpin>(
	buf: &'a mut [u8],
	io: &mut Io,
	pad_with_packet_len: bool,
	block_size: BlockSize,
) -> Result<Packet<'a>, PacketParseError> {
	io.read_exact(&mut buf[..4])
		.await
		.map_err(PacketParseError::Io)?;
	let len = u32::from_be_bytes(buf[..4].try_into().unwrap())
		.try_into()
		.unwrap();
	if len > buf.len() {
		return Err(PacketParseError::TooLarge(len));
	} else if len < 8 {
		return Err(PacketParseError::TooSmall(len));
	}
	io.read_exact(&mut buf[4..][..len])
		.await
		.map_err(PacketParseError::Io)?;
	Packet::wrap_raw(buf, pad_with_packet_len, block_size).map_err(PacketParseError::WrapRaw)
}

#[derive(Debug)]
pub enum PacketParseError {
	TooLarge(usize),
	TooSmall(usize),
	Io(io::Error),
	WrapRaw(WrapRawError),
}
