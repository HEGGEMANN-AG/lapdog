use std::io::{Read, Write};

use crate::{WriteExt, read::ReadExt};

/// Doesn't accept long-form lengths larger than size_of::<usize>() bytes
pub fn read_length<R: Read>(mut r: R) -> std::io::Result<Option<usize>> {
    let first = r.read_single_byte()?;
    match first {
        val @ 0..0x80 => Ok(Some(val.into())),
        0x80 => Ok(None),
        val @ 0x80.. => {
            let length_bytes = (val & 0x7F) as usize;
            if length_bytes > size_of::<usize>() {
                unimplemented!()
            }
            let mut length = [0; size_of::<usize>()];
            r.read_exact(&mut length[size_of::<usize>() - length_bytes..])?;
            Ok(Some(usize::from_be_bytes(length)))
        }
    }
}

pub fn write_length<W: Write>(mut w: W, length: usize) -> std::io::Result<usize> {
    if length < 128 {
        w.write_single_byte(length as u8)?;
        Ok(1)
    } else {
        let mut bytes = Vec::new();
        let mut len = length;
        while len > 0 {
            bytes.push((len & 0x7F) as u8);
            len >>= 8;
        }
        bytes.reverse();

        let num_bytes = bytes.len();
        w.write_single_byte(0x80 | num_bytes as u8)?;
        w.write_all(&bytes)?;
        Ok(1 + num_bytes)
    }
}

#[cfg(test)]
mod test {
    use crate::length::read_length;

    #[test]
    fn read_simple_length() {
        let ten_one = [0x0au8];
        assert_eq!(read_length(ten_one.as_slice()).unwrap(), Some(10));
    }

    #[test]
    fn read_long_length() {
        let ten_two: [u8; 2] = [0x81, 0x0a];
        assert_eq!(read_length(ten_two.as_slice()).unwrap(), Some(10));
    }

    #[test]
    fn read_max_length() {
        let max_long: [u8; 9] = [0x88, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF];
        assert_eq!(read_length(max_long.as_slice()).unwrap(), Some(usize::MAX));
    }
}
