use std::io::Write;

use crate::{
    WriteExt,
    tag::{OCTET_STRING, UNIVERSAL_SEQUENCE},
};

#[derive(Debug, Clone, Copy)]
pub struct AttributeValueAssertion<'d> {
    pub attribute_desc: &'d str,
    pub assertion_value: &'d [u8],
}
impl AttributeValueAssertion<'_> {
    pub fn write_into<W: Write>(&self, w: &mut W) -> std::io::Result<()> {
        w.write_single_byte(UNIVERSAL_SEQUENCE)?;
        let mut seq_inner = Vec::new();
        seq_inner.write_single_byte(OCTET_STRING)?;
        seq_inner.write_ber_length(self.attribute_desc.len())?;
        seq_inner.write_all(self.attribute_desc.as_bytes())?;
        seq_inner.write_single_byte(OCTET_STRING)?;
        seq_inner.write_ber_length(self.assertion_value.len())?;
        seq_inner.write_all(self.assertion_value)?;
        w.write_ber_length(seq_inner.len())?;
        w.write_all(&seq_inner)?;
        Ok(())
    }
}
