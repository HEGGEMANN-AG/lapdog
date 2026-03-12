use std::io::{Read, Write};

use crate::{
    LdapConnection, ResponseProtocolOp, SendMessageError, WriteExt,
    integer::read_integer_body,
    length::read_length,
    message::{ProtocolOp, ReadProtocolOpError, RequestProtocolOp},
    read::ReadExt,
    result::ResultCode,
    tag::{OCTET_STRING, UNIVERSAL_ENUMERATED, UNIVERSAL_SEQUENCE},
};

impl LdapConnection {
    pub async fn compare(
        &mut self,
        entry: &str,
        value_assertion: AttributeValueAssertion<'_>,
    ) -> Result<bool, CompareError> {
        let response = self
            .send_message(RequestProtocolOp::Compare {
                entry,
                value_assertion,
            })
            .await?;
        let ResponseProtocolOp::Compare { compare } =
            ResponseProtocolOp::read_from(&mut response.as_slice())?
        else {
            return Err(CompareError::InvalidSchema);
        };
        Ok(compare)
    }
}

#[derive(Debug)]
pub enum CompareError {
    Io(std::io::Error),
    InvalidSchema,
    Disconnected,
    ServerError { code: ResultCode, message: String },
}
impl From<SendMessageError> for CompareError {
    fn from(value: SendMessageError) -> Self {
        match value {
            SendMessageError::Io(error) => Self::Io(error),
            SendMessageError::ChannelClosed | SendMessageError::ReceiveMessage(_) => Self::Disconnected,
        }
    }
}
impl From<ReadProtocolOpError> for CompareError {
    fn from(value: ReadProtocolOpError) -> Self {
        match value {
            ReadProtocolOpError::Io(error) => Self::Io(error),
            ReadProtocolOpError::ProtocolError { code, message } => Self::ServerError { code, message },
            ReadProtocolOpError::InvalidSchema => Self::InvalidSchema,
        }
    }
}
impl From<std::io::Error> for CompareError {
    fn from(value: std::io::Error) -> Self {
        Self::Io(value)
    }
}

pub(crate) fn write_compare(entry: &str, value_assertion: &AttributeValueAssertion) -> Vec<u8> {
    let mut msg_sequence = Vec::new();
    msg_sequence.push(OCTET_STRING);
    msg_sequence.write_ber_length(entry.len()).expect("infallible");
    msg_sequence.extend_from_slice(entry.as_bytes());
    value_assertion.write_into(&mut msg_sequence).expect("infallible");
    msg_sequence
}

pub(crate) fn read_response<R: Read>(mut r: R) -> Result<bool, ReadCompareError> {
    let tag = r.read_single_byte()?;
    if tag != UNIVERSAL_ENUMERATED {
        return Err(ReadCompareError::InvalidSchema);
    }
    // LdapResult code
    let code = {
        let enum_len = read_length(&mut r)?.ok_or(ReadCompareError::InvalidSchema)?;
        let mut enum_i = vec![0; enum_len];
        r.read_exact(&mut enum_i)?;
        read_integer_body(&enum_i)
            .map_err(|_| ReadCompareError::InvalidSchema)?
            .try_into()
            .ok()
            .and_then(ResultCode::from_code)
            .ok_or(ReadCompareError::InvalidSchema)?
    };
    match code {
        ResultCode::CompareTrue => return Ok(true),
        ResultCode::CompareFalse => return Ok(false),
        _ => {}
    }
    let matched_dn_tag = r.read_single_byte()?;
    if matched_dn_tag != OCTET_STRING {
        return Err(ReadCompareError::InvalidSchema);
    }
    let matched_dn_len = read_length(&mut r)?.ok_or(ReadCompareError::InvalidSchema)?;
    let mut matched_dn = vec![0; matched_dn_len];
    r.read_exact(&mut matched_dn)?;
    let Ok(_) = String::from_utf8(matched_dn) else {
        return Err(ReadCompareError::InvalidSchema);
    };

    let diagnostics_tag = r.read_single_byte()?;
    if diagnostics_tag != OCTET_STRING {
        return Err(ReadCompareError::InvalidSchema);
    }
    let diagnostics_len = read_length(&mut r)?.ok_or(ReadCompareError::InvalidSchema)?;
    let mut message = vec![0; diagnostics_len];
    r.read_exact(&mut message)?;
    let diagnostics_message = String::from_utf8_lossy(&message).to_string();
    Err(ReadCompareError::ServerError {
        code,
        message: diagnostics_message,
    })
}

pub(crate) enum ReadCompareError {
    Io(std::io::Error),
    InvalidSchema,
    ServerError { code: ResultCode, message: String },
}
impl From<std::io::Error> for ReadCompareError {
    fn from(value: std::io::Error) -> Self {
        Self::Io(value)
    }
}

#[derive(Debug, Clone, Copy)]
pub struct AttributeValueAssertion<'d> {
    pub attribute_desc: &'d str,
    pub assertion_value: &'d [u8],
}
impl AttributeValueAssertion<'_> {
    fn write_into<W: Write>(&self, w: &mut W) -> std::io::Result<()> {
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
