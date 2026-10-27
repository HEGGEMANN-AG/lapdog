use std::{
    error::Error,
    fmt::{Display, Formatter, Result as FmtResult},
};

use lapdog::search::FromOctetString;
use uuid::Uuid;

#[derive(Clone, Copy, Debug)]
pub struct Guid(Uuid);
impl Guid {
    pub fn as_uuid(self) -> Uuid {
        self.0
    }
}
impl From<Uuid> for Guid {
    fn from(value: Uuid) -> Self {
        Self(value)
    }
}
impl From<Guid> for Uuid {
    fn from(value: Guid) -> Self {
        value.as_uuid()
    }
}
impl FromOctetString for Guid {
    type Err = InvalidGUID;
    fn from_octet_string(bytes: &[u8]) -> Result<Self, Self::Err> {
        let arr = bytes.as_array().ok_or(InvalidGUID)?;
        let inner = Uuid::from_bytes_le(*arr);
        Ok(Self(inner))
    }
}
impl Display for Guid {
    fn fmt(&self, f: &mut Formatter<'_>) -> FmtResult {
        write!(f, "{}", self.0)
    }
}

#[derive(Debug)]
pub struct InvalidGUID;
impl Error for InvalidGUID {}
impl Display for InvalidGUID {
    fn fmt(&self, f: &mut Formatter<'_>) -> FmtResult {
        write!(f, "Invalid GUID field: invalid byte string length")
    }
}
