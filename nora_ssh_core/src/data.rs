//! Utilities to parse & create common SSH data types.

use core::{fmt, mem, str};

/// A string of only ASCII characters.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct AsciiStr<'a>(&'a str);

impl<'a> TryFrom<&'a [u8]> for AsciiStr<'a> {
    type Error = NotAscii;

    fn try_from(s: &'a [u8]) -> Result<Self, Self::Error> {
        s.is_ascii()
            .then(|| Self(str::from_utf8(s).unwrap()))
            .ok_or(NotAscii)
    }
}

impl<'a, const N: usize> TryFrom<&'a [u8; N]> for AsciiStr<'a> {
    type Error = NotAscii;

    fn try_from(s: &'a [u8; N]) -> Result<Self, Self::Error> {
        Self::try_from(&s[..])
    }
}

impl<'a> From<AsciiStr<'a>> for &'a str {
    fn from(s: AsciiStr<'a>) -> Self {
        s.0
    }
}

impl<'a> From<AsciiStr<'a>> for &'a [u8] {
    fn from(s: AsciiStr<'a>) -> Self {
        <&'a str>::from(s).as_bytes()
    }
}

#[derive(Debug)]
pub struct NotAscii;

/// A comma-separated list of names, e.g. `"none,publickey,password"`.
#[derive(Clone, Copy)]
pub struct NameList<'a>(&'a str);

impl<'a> NameList<'a> {
    #[inline]
    pub fn iter(&self) -> NameListIter<'a> {
        NameListIter(self.0)
    }
}

impl<'a> TryFrom<&'a [u8]> for NameList<'a> {
    type Error = InvalidNameList;

    fn try_from(list: &'a [u8]) -> Result<Self, Self::Error> {
        if !list.is_ascii() {
            Err(InvalidNameList::NotAscii)
        } else if list.windows(2).any(|c| c == b",,") {
            Err(InvalidNameList::EmptyName)
        } else if list.first() == Some(&b',') || list.last() == Some(&b',') {
            Err(InvalidNameList::EmptyName)
        } else {
            Ok(Self(str::from_utf8(list).unwrap()))
        }
    }
}

impl<'a, const N: usize> TryFrom<&'a [u8; N]> for NameList<'a> {
    type Error = InvalidNameList;

    fn try_from(list: &'a [u8; N]) -> Result<Self, Self::Error> {
        Self::try_from(&list[..])
    }
}

impl<'a> From<NameList<'a>> for &'a str {
    fn from(s: NameList<'a>) -> Self {
        s.0
    }
}

impl<'a> From<NameList<'a>> for &'a [u8] {
    fn from(s: NameList<'a>) -> Self {
        <&'a str>::from(s).as_bytes()
    }
}

impl fmt::Debug for NameList<'_> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.debug_list().entries(self.iter()).finish()
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum InvalidNameList {
    EmptyName,
    NotAscii,
}

pub struct NameListIter<'a>(&'a str);

impl<'a> Iterator for NameListIter<'a> {
    type Item = &'a str;

    fn next(&mut self) -> Option<Self::Item> {
        if self.0.is_empty() {
            None
        } else if let Some(i) = self.0.bytes().position(|c| c == b',') {
            let l = mem::take(&mut self.0);
            self.0 = &l[i + 1..];
            Some(&l[..i])
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

pub(crate) fn make_string2<'a>(buf: &'a mut [u8], s: &[u8]) -> Option<(usize, &'a mut [u8])> {
    buf.get_mut(..4)?
        .copy_from_slice(&u32::try_from(s.len()).unwrap().to_be_bytes());
    buf.get_mut(4..4 + s.len())?.copy_from_slice(s);
    Some((4 + s.len(), &mut buf[4 + s.len()..]))
}

pub(crate) fn make_bool(buf: &mut [u8], value: bool) -> Option<(usize, &mut [u8])> {
    let (v, buf) = buf.split_first_mut()?;
    *v = u8::from(value);
    Some((1, buf))
}

pub(crate) fn make_raw<'a>(buf: &'a mut [u8], data: &[u8]) -> Option<(usize, &'a mut [u8])> {
    (data.len() <= buf.len()).then(|| {
        let (cpy, buf) = buf.split_at_mut(data.len());
        cpy.copy_from_slice(data);
        (cpy.len(), buf)
    })
}

pub(crate) fn parse_string(s: &[u8]) -> Option<&[u8]> {
    parse_string2(s).map(|(s, _)| s)
}

pub(crate) fn parse_string2(s: &[u8]) -> Option<(&[u8], usize)> {
    let len = u32::from_be_bytes(s.get(..4)?.try_into().unwrap());
    let i = 4 + usize::try_from(len).unwrap();
    s.get(4..i).map(|s| (s, i))
}

pub(crate) fn parse_string3(s: &[u8]) -> Option<(&[u8], &[u8])> {
    parse_string2(s).map(|(v, i)| (v, &s[i..]))
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

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn name_list() {
        let mut list = NameList::try_from(b"foo,bar,baz,qux").unwrap().iter();
        assert_eq!(list.next(), Some("foo"));
        assert_eq!(list.next(), Some("bar"));
        assert_eq!(list.next(), Some("baz"));
        assert_eq!(list.next(), Some("qux"));
        assert_eq!(list.next(), None);
    }

    #[test]
    fn name_list_empty_name() {
        assert_eq!(
            NameList::try_from(b"foo,,bar").unwrap_err(),
            InvalidNameList::EmptyName
        );
        assert_eq!(
            NameList::try_from(b",foo,bar").unwrap_err(),
            InvalidNameList::EmptyName
        );
        assert_eq!(
            NameList::try_from(b"foo,bar,").unwrap_err(),
            InvalidNameList::EmptyName
        );
    }

    #[test]
    fn name_list_not_ascii() {
        assert_eq!(
            NameList::try_from(b"foo,\xb5,bar").unwrap_err(),
            InvalidNameList::NotAscii
        );
    }
}
