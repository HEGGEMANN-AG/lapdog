use std::{
    cmp::Ordering,
    error::Error,
    fmt::{Debug, Display, Formatter, Result as FmtResult},
    num::NonZero,
};

use lapdog::search::FromOctetString;

#[derive(Clone)]
pub struct SID(Vec<u8>);

impl SID {
    pub fn new(bytes: &[u8]) -> Result<Self, InvalidSID> {
        Self::from_vec(bytes.to_vec())
    }
    pub fn from_vec(vec: Vec<u8>) -> Result<Self, InvalidSID> {
        if *vec.first().ok_or(InvalidSID::TooShort)? != 1 {
            return Err(InvalidSID::UnknownRevision);
        }
        let sub_authority_count = *vec.get(1).ok_or(InvalidSID::TooShort)?;
        if sub_authority_count == 0 {
            return Err(InvalidSID::NoRelativePart);
        }
        match vec.len().cmp(&((8 + sub_authority_count * 4) as usize)) {
            Ordering::Equal => Ok(Self(vec)),
            Ordering::Less => Err(InvalidSID::TooShort),
            Ordering::Greater => Err(InvalidSID::MismatchedLength),
        }
    }
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
    pub fn revision(&self) -> u8 {
        self.0[0]
    }
    pub fn sub_authority_count(&self) -> NonZero<u8> {
        // # Safety
        // Checked in constructor
        unsafe { NonZero::new_unchecked(self.0[1]) }
    }
    /// Returns the bytes as-is (big-endian)
    pub fn authority(&self) -> [u8; 6] {
        // # Safety
        // Length checked in constructor
        unsafe { *self.0[2..8].as_array().unwrap_unchecked() }
    }
    pub fn authority_u64(&self) -> u64 {
        let mut authority = [0; 8];
        authority[2..].copy_from_slice(&self.0[2..8]);
        u64::from_be_bytes(authority)
    }

    pub fn rid(&self) -> u32 {
        // # Safety
        // Checked in constructor
        unsafe { self.subauthorities().last().unwrap_unchecked() }
    }

    pub fn get_subauthority(&self, index: u8) -> Option<u32> {
        let (chunks, _) = self.0[8..].as_chunks();
        chunks.get(index as usize).copied().map(u32::from_le_bytes)
    }
    pub fn subauthorities(&self) -> impl ExactSizeIterator<Item = u32> + DoubleEndedIterator {
        self.0[8..].as_chunks().0.iter().copied().map(u32::from_le_bytes)
    }
}

impl Debug for SID {
    fn fmt(&self, f: &mut Formatter<'_>) -> FmtResult {
        <Self as Display>::fmt(self, f)
    }
}

impl Display for SID {
    fn fmt(&self, f: &mut Formatter<'_>) -> FmtResult {
        write!(f, "S-{}-{}", self.revision(), self.authority_u64())?;
        for authority in self.subauthorities() {
            write!(f, "-{authority}")?;
        }
        Ok(())
    }
}

#[derive(Debug, Clone)]
pub enum InvalidSID {
    UnknownRevision,
    TooShort,
    NoRelativePart,
    MismatchedLength,
}
impl Error for InvalidSID {}
impl Display for InvalidSID {
    fn fmt(&self, f: &mut Formatter<'_>) -> FmtResult {
        match self {
            Self::UnknownRevision => write!(f, "unknown revision bytes"),
            Self::TooShort => write!(f, "the byte stream ended early"),
            Self::NoRelativePart => write!(f, "No relative subauthorities are given"),
            Self::MismatchedLength => write!(f, "more bytes than sub-authority count suggests"),
        }
    }
}

impl FromOctetString for SID {
    type Err = InvalidSID;
    fn from_octet_string(bytes: &[u8]) -> Result<Self, Self::Err> {
        Self::new(bytes)
    }
}
