#[derive(Clone, Copy)]
pub struct Identifier<'a>(&'a [u8]);

impl<'a> Identifier<'a> {
    pub const MAX_LEN: usize = 255 - b"\r\n".len();

    pub fn new(ident: &'a [u8]) -> Option<Self> {
        (ident.len() <= Self::MAX_LEN).then(|| Self(ident))
    }
}

impl AsRef<[u8]> for Identifier<'_> {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}
