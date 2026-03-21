use std::io::Read;

use crate::{length::LengthError, read::ReadExt};

mod integer;

pub trait ParseLdap: ReadExt {
    fn read_as_tag_integer(&mut self) -> Result<(u8, i32), ReadIntegerError> {
        let tag = self.read_single_byte().map_err(ReadIntegerError::Io)?;
        let length = self.read_ber_length().map_err(ReadIntegerError::Length)?;
        if length > 6 {
            return Err(ReadIntegerError::OutOfRange);
        }
        let mut int_body = [0u8; 6];
        self.read_exact(&mut int_body[0..length])
            .map_err(ReadIntegerError::Io)?;
        let i =
            integer::read_integer_body(&int_body[0..length]).map_err(|_m| ReadIntegerError::OutOfRange)?;
        Ok((tag, i))
    }
    fn read_ber_length(&mut self) -> Result<usize, LengthError> {
        let first = self.read_single_byte().map_err(LengthError::Io)?;
        match first {
            val @ 0..0x80 => Ok(val.into()),
            0x80 => Err(LengthError::Unbounded),
            val @ 0x80.. => {
                let length_bytes = (val & 0x7F) as usize;
                if length_bytes > size_of::<usize>() {
                    return Err(LengthError::OutOfRange);
                }
                let mut length = [0; size_of::<usize>()];
                self.read_exact(&mut length[size_of::<usize>() - length_bytes..])
                    .map_err(LengthError::Io)?;
                Ok(usize::from_be_bytes(length))
            }
        }
    }
}
impl<T: Read> ParseLdap for T {}

#[derive(Debug)]
pub enum ReadIntegerError {
    Io(std::io::Error),
    Length(LengthError),
    OutOfRange,
}
