use std::{
    convert::Infallible,
    fmt::Display,
    num::{NonZeroI8, NonZeroI16, NonZeroI32, NonZeroI64, NonZeroU8, NonZeroU16, NonZeroU32, NonZeroU64, Saturating},
};

use crate::search::FromOctetString;

impl FromOctetString for String {
    type Err = std::string::FromUtf8Error;
    fn from_octet_string(bytes: &[u8]) -> Result<Self, Self::Err> {
        String::from_utf8(bytes.to_vec())
    }
}
impl FromOctetString for () {
    type Err = Infallible;
    fn from_octet_string(_bytes: &[u8]) -> Result<Self, Self::Err> {
        Ok(())
    }
}
impl<T: FromOctetString> FromOctetString for Box<T> {
    type Err = T::Err;
    fn from_octet_string(bytes: &[u8]) -> Result<Self, Self::Err> {
        Ok(Box::new(T::from_octet_string(bytes)?))
    }
}
macro_rules! from_octet_for_integer {
    ($t:ty) => {
        impl FromOctetString for $t {
            type Err = ParseIntegerError;
            fn from_octet_string(bytes: &[u8]) -> Result<Self, Self::Err> {
                let s = str::from_utf8(bytes).map_err(ParseIntegerError::Utf8)?;
                s.parse::<$t>().map_err(ParseIntegerError::Parse)
            }
        }
    };
}
impl<T: FromOctetString> FromOctetString for Saturating<T> {
    type Err = T::Err;
    fn from_octet_string(bytes: &[u8]) -> Result<Self, Self::Err> {
        Ok(Saturating(T::from_octet_string(bytes)?))
    }
}
from_octet_for_integer!(u8);
from_octet_for_integer!(u16);
from_octet_for_integer!(u32);
from_octet_for_integer!(u64);
from_octet_for_integer!(i8);
from_octet_for_integer!(i16);
from_octet_for_integer!(i32);
from_octet_for_integer!(i64);
from_octet_for_integer!(NonZeroI8);
from_octet_for_integer!(NonZeroI16);
from_octet_for_integer!(NonZeroI32);
from_octet_for_integer!(NonZeroI64);
from_octet_for_integer!(NonZeroU8);
from_octet_for_integer!(NonZeroU16);
from_octet_for_integer!(NonZeroU32);
from_octet_for_integer!(NonZeroU64);

#[derive(Clone, Debug)]
pub enum ParseIntegerError {
    Utf8(std::str::Utf8Error),
    Parse(std::num::ParseIntError),
}
impl std::error::Error for ParseIntegerError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Parse(p) => Some(p),
            Self::Utf8(utf8) => Some(utf8),
        }
    }
}
impl Display for ParseIntegerError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Utf8(u) => write!(f, "server response is not utf-8: {u}"),
            Self::Parse(p) => write!(f, "failed to parse integer from response: {p}"),
        }
    }
}
