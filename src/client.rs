use crate::cipher::Cipher;

pub struct Client<D: Cipher> {
    receive_cipher: D,
    send_cipher: D,
}

impl<D: Cipher> Client<D> {}
