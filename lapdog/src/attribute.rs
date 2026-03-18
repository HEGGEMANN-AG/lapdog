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
    pub(crate) fn write_into<W: Write>(&self, w: &mut W) -> std::io::Result<()> {
        let mut seq_inner = Vec::new();
        self.write_body_into(&mut seq_inner)?;

        w.write_single_byte(UNIVERSAL_SEQUENCE)?;
        w.write_ber_length(seq_inner.len())?;
        w.write_all(&seq_inner)?;
        Ok(())
    }
    pub(crate) fn write_body_into<W: Write>(&self, w: &mut W) -> std::io::Result<()> {
        w.write_single_byte(OCTET_STRING)?;
        w.write_ber_length(self.attribute_desc.len())?;
        w.write_all(self.attribute_desc.as_bytes())?;
        w.write_single_byte(OCTET_STRING)?;
        w.write_ber_length(self.assertion_value.len())?;
        w.write_all(self.assertion_value)?;
        Ok(())
    }
}
impl<'d> AttributeValueAssertion<'d> {
    pub const fn new(attribute_desc: &'d str, assertion_value: &'d [u8]) -> Self {
        Self {
            attribute_desc,
            assertion_value,
        }
    }
}
