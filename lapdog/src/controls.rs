use crate::{
    WriteExt,
    oid::OidRef,
    tag::{OCTET_STRING, UNIVERSAL_BOOLEAN, UNIVERSAL_SEQUENCE},
};

#[derive(Clone, Debug)]
pub struct ControlRef<'r> {
    pub oid: OidRef<'r>,
    pub criticality: bool,
    pub control_value: Option<Vec<u8>>,
}
impl<'r> ControlRef<'r> {
    pub fn write_into(&self, v: &mut Vec<u8>) {
        v.write_sequence(UNIVERSAL_SEQUENCE, |buf| {
            buf.push(OCTET_STRING);
            let str = self.oid.to_string();
            buf.write_ber_length(str.len()).expect("infallible for Vec");
            buf.extend_from_slice(str.as_bytes());
            buf.push(UNIVERSAL_BOOLEAN);
            buf.write_ber_length(1).expect("infallible for Vec");
            buf.push(if self.criticality { 0xFF } else { 0x00 });
            if let Some(val) = &self.control_value {
                buf.push(OCTET_STRING);
                buf.write_ber_length(val.len()).expect("infallible for Vec");
                buf.extend_from_slice(val);
            };
            Ok(())
        })
        .expect("infallible for Vec");
    }
}
