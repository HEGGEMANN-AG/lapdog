use std::io::Read;

use crate::{
    LdapConnection, ResponseProtocolOp, SendMessageError, WriteExt,
    attribute::AttributeValueAssertion,
    length::{LengthError, read_length},
    message::{ProtocolOp, ReadProtocolOpError, RequestProtocolOp},
    parse::{ParseLdap, ReadIntegerError},
    read::ReadExt,
    result::ResultCode,
    tag::{OCTET_STRING, UNIVERSAL_ENUMERATED},
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
            .await?
            .into_message();
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
    let (tag, code) = r.read_as_tag_integer().unwrap();
    if tag != UNIVERSAL_ENUMERATED {
        return Err(ReadCompareError::InvalidSchema);
    }

    // LdapResult code
    let code = code
        .try_into()
        .ok()
        .and_then(ResultCode::from_code)
        .ok_or(ReadCompareError::InvalidSchema)?;
    match code {
        ResultCode::CompareTrue => return Ok(true),
        ResultCode::CompareFalse => return Ok(false),
        _ => {}
    }
    let matched_dn_tag = r.read_single_byte()?;
    if matched_dn_tag != OCTET_STRING {
        return Err(ReadCompareError::InvalidSchema);
    }
    let matched_dn_len = read_length(&mut r)?;
    let mut matched_dn = vec![0; matched_dn_len];
    r.read_exact(&mut matched_dn)?;
    let Ok(_) = String::from_utf8(matched_dn) else {
        return Err(ReadCompareError::InvalidSchema);
    };

    let diagnostics_tag = r.read_single_byte()?;
    if diagnostics_tag != OCTET_STRING {
        return Err(ReadCompareError::InvalidSchema);
    }
    let diagnostics_len = read_length(&mut r)?;
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
impl From<LengthError> for ReadCompareError {
    fn from(value: LengthError) -> Self {
        match value {
            LengthError::Io(error) => Self::Io(error),
            LengthError::Unbounded | LengthError::OutOfRange => Self::InvalidSchema,
        }
    }
}
impl From<ReadIntegerError> for ReadCompareError {
    fn from(value: ReadIntegerError) -> Self {
        match value {
            ReadIntegerError::Io(error) => Self::Io(error),
            ReadIntegerError::Length(_) | ReadIntegerError::OutOfRange => Self::InvalidSchema,
        }
    }
}
