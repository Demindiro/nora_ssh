use core::mem;

/// A comma-separated list of names, e.g. `"chacha20-poly1305@openssh.com,aes128-ctr,aes192-ctr"`.
#[derive(Clone, Copy)]
pub struct NameList<'a>(&'a [u8]);

impl<'a> NameList<'a> {
    #[inline]
    pub fn iter(&self) -> NameListIter<'a> {
        NameListIter(self.0)
    }
}

pub struct NameListIter<'a>(&'a [u8]);

impl<'a> Iterator for NameListIter<'a> {
    type Item = &'a [u8];

    fn next(&mut self) -> Option<Self::Item> {
        if self.0.is_empty() {
            None
        } else if let Some(i) = self.0.iter().position(|&c| c == b',') {
            Some(&mem::replace(&mut self.0, &self.0[i..])[..i])
        } else {
            Some(mem::take(&mut self.0))
        }
    }
}

pub(crate) fn split(data: &[u8], i: usize) -> Option<(&[u8], &[u8])> {
    (data.len() >= i).then(|| data.split_at(i))
}

pub(crate) fn name_list(data: &[u8]) -> Option<(&[u8], &[u8])> {
    let (len, data) = split(data, 4)?;
    let len = u32::from_be_bytes(len.try_into().unwrap())
        .try_into()
        .unwrap();
    split(data, len)
}

pub(crate) fn make_string_len(s: &[u8]) -> [u8; 4] {
    u32::try_from(s.len()).unwrap().to_be_bytes()
}

pub(crate) fn make_string<'a>(buf: &'a mut [u8], s: &[u8]) -> Option<(&'a mut [u8], &'a mut [u8])> {
    buf.get_mut(..4)?
        .copy_from_slice(&u32::try_from(s.len()).unwrap().to_be_bytes());
    buf.get_mut(4..4 + s.len())?.copy_from_slice(s);
    Some(buf.split_at_mut(4 + s.len()))
}

pub(crate) fn parse_string(s: &[u8]) -> Option<&[u8]> {
    parse_string2(s).map(|(s, _)| s)
}

pub(crate) fn parse_string2(s: &[u8]) -> Option<(&[u8], usize)> {
    let len = u32::from_be_bytes(s.get(..4)?.try_into().unwrap());
    let i = 4 + usize::try_from(len).unwrap();
    s.get(4..i).map(|s| (s, i))
}

pub(crate) fn make_pos_mpint<'a>(buf: &'a mut [u8], mut s: &[u8]) -> Option<usize> {
    // Remove redundant zeroes
    while s.get(0) == Some(&0) {
        s = &s[1..];
    }
    // Prepend a zero to ensure the number is interpreted as positive
    let i = if s.get(0).map_or(false, |&c| c & 0x80 != 0) {
        *buf.get_mut(4)? = 0;
        1
    } else {
        0
    };
    buf.get_mut(..4)?
        .copy_from_slice(&u32::try_from(i + s.len()).unwrap().to_be_bytes());
    buf.get_mut(4 + i..4 + i + s.len())?.copy_from_slice(s);
    Some(4 + i + s.len())
}
