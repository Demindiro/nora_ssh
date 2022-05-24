use crate::data::{make_string2, parse_string};

macro_rules! impl_s {
    ($name:ident ? $err:ident) => {
        pub struct $name<'a> {
            service_name: &'a [u8],
        }

        impl<'a> $name<'a> {
            pub fn new(service_name: &'a [u8]) -> Self {
                Self { service_name }
            }

            pub fn parse(data: &'a [u8]) -> Result<Self, $err> {
                parse_string(data)
                    .and_then(|s| (s.len() + 4 == data.len()).then(|| s))
                    .map(Self::new)
                    .ok_or($err::BadLength)
            }

            pub fn serialize(&self, buf: &mut [u8]) -> Option<usize> {
                let (a, _) = make_string2(buf, self.service_name)?;
                Some(a)
            }
        }

        impl<'a> From<$name<'a>> for &'a [u8] {
            fn from(s: $name<'a>) -> Self {
                s.service_name
            }
        }

        impl<'a> From<&'a [u8]> for $name<'a> {
            fn from(service_name: &'a [u8]) -> Self {
                Self { service_name }
            }
        }

        impl<'a> From<&'a str> for $name<'a> {
            fn from(service_name: &'a str) -> Self {
                Self::from(service_name.as_bytes())
            }
        }

        #[derive(Debug)]
        pub enum $err {
            BadLength,
        }
    };
}

impl_s!(ServiceRequest ? ParseServiceRequestError);
impl_s!(ServiceAccept ? ParseServiceAcceptError);
