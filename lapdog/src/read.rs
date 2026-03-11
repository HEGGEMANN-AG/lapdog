use std::io::Read;

use tokio::io::AsyncReadExt;

use crate::{
    integer::read_integer_body,
    tag::{PrimitiveOrConstructed, TagClass, is_tag_triple},
};

pub(crate) trait ReadExt: Read {
    fn read_single_byte(&mut self) -> std::io::Result<u8> {
        let mut b = 0;
        self.read_exact(std::slice::from_mut(&mut b))?;
        Ok(b)
    }
}
impl<R: Read> ReadExt for R {}
pub(crate) trait ReadLdap: ReadExt {
    fn read_message_head(&mut self) -> Result<(i32, Vec<u8>), ReadLdapError> {
        let seq_tag = self.read_single_byte().map_err(ReadLdapError::Io)?;
        if !is_tag_triple(
            seq_tag,
            crate::tag::TagClass::Universal,
            PrimitiveOrConstructed::Constructed,
            0b00010000,
        ) {
            return Err(ReadLdapError::InvalidSequenceTag);
        }
        let (seq_length, _) = self.read_length().map_err(ReadLdapError::Io)?;
        let seq_length = seq_length.unwrap();
        let (int_tag, message_id, int_len) = self.read_integer_unverified().map_err(ReadLdapError::Io)?;
        if !is_tag_triple(
            int_tag,
            TagClass::Universal,
            PrimitiveOrConstructed::Primitive,
            0x02,
        ) {
            panic!("not an integer");
        }

        let mut buffer = vec![0; seq_length - int_len];
        self.read_exact(&mut buffer).map_err(ReadLdapError::Io)?;
        Ok((message_id, buffer))
    }
    /// Returns logical length of object, and then number of read bytes
    fn read_length(&mut self) -> std::io::Result<(Option<usize>, usize)> {
        let first = self.read_single_byte()?;
        match first {
            val @ 0..0x80 => Ok((Some(val.into()), 1)),
            0x80 => Ok((None, 1)),
            val @ 0x80.. => {
                let length_bytes = (val & 0x7F) as usize;
                if length_bytes > size_of::<usize>() {
                    unimplemented!()
                }
                let mut length = [0; size_of::<usize>()];
                self.read_exact(&mut length[size_of::<usize>() - length_bytes..])?;
                Ok((Some(usize::from_be_bytes(length)), 1 + length_bytes))
            }
        }
    }
    fn read_integer_unverified(&mut self) -> std::io::Result<(u8, i32, usize)> {
        let int_tag = self.read_single_byte()?;
        let (Some(int_len), len_len) = self.read_length()? else {
            panic!("Length undefined");
        };
        let mut intbuf = vec![0; int_len];
        self.read_exact(&mut intbuf)?;
        let i = read_integer_body(&intbuf).unwrap();
        Ok((int_tag, i, 1 + len_len + int_len))
    }
}
impl<T: Read> ReadLdap for T {}

#[derive(Debug)]
pub enum ReadLdapError {
    InvalidSequenceTag,
    Io(std::io::Error),
}

pub(crate) trait AsyncReadLdap: AsyncReadExt + Unpin {
    async fn read_message_head(&mut self) -> Result<(i32, Vec<u8>), ReadLdapError> {
        let seq_tag = self.read_u8().await.map_err(ReadLdapError::Io)?;
        if !is_tag_triple(
            seq_tag,
            crate::tag::TagClass::Universal,
            PrimitiveOrConstructed::Constructed,
            0b00010000,
        ) {
            return Err(ReadLdapError::InvalidSequenceTag);
        }
        let (seq_length, _) = self.read_length().await.map_err(ReadLdapError::Io)?;
        let seq_length = seq_length.unwrap();
        let (int_tag, message_id, int_len) =
            self.read_integer_unverified().await.map_err(ReadLdapError::Io)?;
        if !is_tag_triple(
            int_tag,
            TagClass::Universal,
            PrimitiveOrConstructed::Primitive,
            0x02,
        ) {
            panic!("not an integer");
        }

        let mut buffer = vec![0; seq_length - int_len];
        self.read_exact(&mut buffer).await.map_err(ReadLdapError::Io)?;
        Ok((message_id, buffer))
    }
    /// Returns logical length of object, and then number of read bytes
    async fn read_length(&mut self) -> std::io::Result<(Option<usize>, usize)> {
        let first = self.read_u8().await?;
        match first {
            val @ 0..0x80 => Ok((Some(val.into()), 1)),
            0x80 => Ok((None, 1)),
            val @ 0x80.. => {
                let length_bytes = (val & 0x7F) as usize;
                if length_bytes > size_of::<usize>() {
                    unimplemented!()
                }
                let mut length = [0; size_of::<usize>()];
                self.read_exact(&mut length[size_of::<usize>() - length_bytes..])
                    .await?;
                Ok((Some(usize::from_be_bytes(length)), 1 + length_bytes))
            }
        }
    }
    async fn read_integer_unverified(&mut self) -> std::io::Result<(u8, i32, usize)> {
        let int_tag = self.read_u8().await?;
        let (Some(int_len), len_len) = self.read_length().await? else {
            panic!("Length undefined");
        };
        let mut intbuf = vec![0; int_len];
        self.read_exact(&mut intbuf).await?;
        let i = read_integer_body(&intbuf).unwrap();
        Ok((int_tag, i, 1 + len_len + int_len))
    }
}
impl<T: AsyncReadExt + Unpin> AsyncReadLdap for T {}
