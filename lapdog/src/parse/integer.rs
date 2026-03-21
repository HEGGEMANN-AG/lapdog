use std::{error::Error, fmt::Display};

/// Does not include type or length
pub fn read_integer_body(arr: &[u8]) -> Result<i32, InvalidI32> {
    if arr.is_empty() {
        return Err(InvalidI32::Empty);
    }
    let first = arr[0];
    let is_negative = (first & 0x80) != 0;
    match arr.len() {
        0 => unreachable!(),
        1 => Ok(first as i8 as i32),
        2..6 => {
            let second = arr[1];
            let second_is_negative = (second & 0x80) != 0;
            if (second_is_negative && first == 0xFF) || (!second_is_negative && first == 0x00) {
                return Err(InvalidI32::OutOfRange);
            }
            if arr.len() == 5 && first != 0x00 && first != 0xFF {
                return Err(InvalidI32::OutOfRange);
            }
            let mut value = if is_negative { -1i64 } else { 0i64 }.to_be_bytes();
            value[(size_of::<i64>() - arr.len())..].copy_from_slice(arr);
            let fix_arr: [u8; 4] = value[4..].try_into().unwrap();
            Ok(i32::from_be_bytes(fix_arr))
        }
        6.. => Err(InvalidI32::OutOfRange),
    }
}

#[derive(Clone, Copy, Debug, PartialEq)]
pub enum InvalidI32 {
    Empty,
    OutOfRange,
}
impl Error for InvalidI32 {}
impl Display for InvalidI32 {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Empty => write!(f, "no bytes sent"),
            Self::OutOfRange => write!(f, "Integer out of range"),
        }
    }
}

#[cfg(test)]
mod test {

    use super::{InvalidI32, read_integer_body};
    #[test]
    fn test_ber_i32() {
        let cases: Vec<(&[u8], Result<i32, InvalidI32>)> = vec![
            // (bytes, expected i32)
            (&[0x00], Ok(0)),
            (&[0x01], Ok(1)),
            (&[0x7F], Ok(127)),
            (&[0x00, 0x80], Ok(128)),
            (&[0x7F, 0xFF], Ok(32_767)),
            (&[0x00, 0x80, 0x00], Ok(32_768)),
            (&[0xFF], Ok(-1)),
            (&[0x80], Ok(-128)),
            (&[0xFF, 0x7F], Ok(-129)),
            (&[0xFF, 0xFF, 0xFF, 0xFF], Err(InvalidI32::OutOfRange)),
            (&[0xFF, 0xFF, 0xFF, 0xFF, 0xFF], Err(InvalidI32::OutOfRange)),
            (&[0x80, 0x00, 0x00, 0x00], Ok(i32::MIN)),
            (&[0x7F, 0xFF, 0xFF, 0xFF], Ok(i32::MAX)),
        ];

        for (bytes, expected) in cases {
            assert_eq!(read_integer_body(bytes), expected);
        }
    }
}
