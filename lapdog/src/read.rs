use std::io::Read;

use tokio::io::AsyncReadExt;

pub(crate) trait ReadExt: Read {
    fn read_single_byte(&mut self) -> std::io::Result<u8> {
        let mut b = 0;
        self.read_exact(std::slice::from_mut(&mut b))?;
        Ok(b)
    }
}
impl<R: Read> ReadExt for R {}

pub(crate) trait ReadLdap: ReadExt {
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
}
impl<T: Read> ReadLdap for T {}

pub(crate) trait AsyncReadLdap: AsyncReadExt + Unpin {
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
}
impl<T: AsyncReadExt + Unpin> AsyncReadLdap for T {}
