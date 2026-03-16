use std::{collections::VecDeque, io::Write};

use crate::WriteExt;

pub fn write_integer<W: Write>(i: i32, mut w: W) -> std::io::Result<usize> {
    if i == 0 {
        w.write_single_byte(0)?;
        return Ok(1);
    }
    let mut v = VecDeque::new();
    v.extend(i.to_be_bytes());
    while v.len() > 1 {
        if (v[0] == 0xFF && v[1] & 0x80 != 0) || (v[0] == 0x00 && v[1] & 0x80 == 0) {
            v.pop_front();
        } else {
            break;
        }
    }
    if i > 0 && v[0] & 0x80 != 0 {
        v.push_front(0);
    }
    let con = v.make_contiguous();
    w.write_all(con)?;
    Ok(con.len())
}
