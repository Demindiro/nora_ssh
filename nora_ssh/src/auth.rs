pub enum Auth<'a> {
	None,
	Password(&'a [u8]),
	PublicKey { algorithm: &'a [u8], key: &'a [u8], signature: &'a [u8], message: &'a [u8] },
}
