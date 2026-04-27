use std::{
    fmt::{Display, Formatter, Result as FmtResult},
    io::Read,
};

use crate::{
    LdapConnection, ResponseProtocolOp, WriteExt,
    length::{LengthError, read_length},
    message::{ProtocolOp, ReadProtocolOpError, RequestProtocolOp},
    parse::{ParseLdap, ReadIntegerError},
    read::ReadExt,
    result::ResultCode,
    tag::{OCTET_STRING, UNIVERSAL_ENUMERATED, UNIVERSAL_SEQUENCE, UNIVERSAL_SET},
};

impl LdapConnection {
    pub async fn modify(&mut self, object: &str, changes: &[Change<'_>]) -> Result<(), ModifyError> {
        let response = self
            .send_message(RequestProtocolOp::Modify { object, changes })
            .await
            .unwrap()
            .into_message();
        let ResponseProtocolOp::Modify = ResponseProtocolOp::read_from(&mut response.as_slice())? else {
            return Err(ModifyError::InvalidSchema);
        };
        read_response(&mut response.as_slice()).map_err(|err| match err {
            ReadModifyError::InvalidSchema => ModifyError::InvalidSchema,
            ReadModifyError::Io(error) => ModifyError::Io(error),
            ReadModifyError::ServerError { code, message } => ModifyError::ServerError { code, message },
        })?;
        Ok(())
    }
}

#[derive(Debug)]
pub enum ModifyError {
    Io(std::io::Error),
    InvalidSchema,
    Disconnected,
    ServerError { code: ResultCode, message: String },
}
impl From<ReadProtocolOpError> for ModifyError {
    fn from(value: ReadProtocolOpError) -> Self {
        match value {
            ReadProtocolOpError::Io(error) => Self::Io(error),
            ReadProtocolOpError::ServerError { code, message } => Self::ServerError { code, message },
            ReadProtocolOpError::InvalidSchema => Self::InvalidSchema,
        }
    }
}
impl std::error::Error for ModifyError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Io(io) => Some(io),
            Self::Disconnected | Self::InvalidSchema | Self::ServerError { .. } => None,
        }
    }
}
impl Display for ModifyError {
    fn fmt(&self, f: &mut Formatter<'_>) -> FmtResult {
        match self {
            Self::Io(error) => write!(f, "An IO error occured: {error}"),
            Self::InvalidSchema => write!(f, "Server returned an invalid message"),
            Self::Disconnected => write!(f, "Connection disconnected"),
            Self::ServerError { code, message } => {
                write!(f, "Server returned an error. Code: {code:?} (\"{message}\")",)
            }
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum Operation {
    Add,
    Delete,
    Replace,
}
impl Operation {
    pub fn to_int(self) -> u8 {
        match self {
            Operation::Add => 0,
            Operation::Delete => 1,
            Operation::Replace => 2,
        }
    }
    pub fn from_int(u: u8) -> Option<Self> {
        match u {
            0 => Some(Self::Add),
            1 => Some(Self::Delete),
            2 => Some(Self::Replace),
            _ => None,
        }
    }
    pub(crate) fn write_into(self, v: &mut Vec<u8>) {
        v.push(UNIVERSAL_ENUMERATED);
        let mut int_bytes = Vec::new();
        int_bytes.write_ber_integer_body(self.to_int().into()).unwrap();
        v.write_ber_length(int_bytes.len()).unwrap();
        v.extend(int_bytes);
    }
}

#[derive(Clone, Copy, Debug)]
pub struct Change<'c> {
    pub operation: Operation,
    pub attribute_type: &'c str,
    pub attribute_values: &'c [&'c [u8]],
}

pub(crate) fn write_modify(object: &str, changes: &[Change]) -> Vec<u8> {
    let mut msg_sequence = Vec::new();
    msg_sequence.push(OCTET_STRING);
    msg_sequence.write_ber_length(object.len()).expect("infallible");
    msg_sequence.extend_from_slice(object.as_bytes());
    msg_sequence
        .write_sequence(UNIVERSAL_SEQUENCE, |changes_msg| {
            for change in changes {
                changes_msg.write_sequence(UNIVERSAL_SEQUENCE, |change_msg| {
                    change.operation.write_into(change_msg);

                    change_msg.write_sequence(UNIVERSAL_SEQUENCE, |modification| {
                        modification.push(OCTET_STRING);
                        modification
                            .write_ber_length(change.attribute_type.len())
                            .expect("infallible");
                        modification.extend_from_slice(change.attribute_type.as_bytes());

                        modification.write_sequence(UNIVERSAL_SET, |partial_attr_values| {
                            for val in change.attribute_values {
                                partial_attr_values.push(OCTET_STRING);
                                partial_attr_values
                                    .write_ber_length(val.len())
                                    .expect("infallible");
                                partial_attr_values.extend_from_slice(val);
                            }
                            Ok(())
                        })?;
                        Ok(())
                    })
                })?;
            }
            Ok(())
        })
        .expect("infallible");
    msg_sequence
}

pub(crate) fn read_response<R: Read>(mut r: R) -> Result<(), ReadModifyError> {
    let (tag, code) = r.read_as_tag_integer()?;
    if tag != UNIVERSAL_ENUMERATED {
        return Err(ReadModifyError::InvalidSchema);
    }

    // LdapResult code
    let code = code
        .try_into()
        .ok()
        .and_then(ResultCode::from_code)
        .ok_or(ReadModifyError::InvalidSchema)?;
    if let ResultCode::Success = code {
        return Ok(());
    }
    let matched_dn_tag = r.read_single_byte()?;
    if matched_dn_tag != OCTET_STRING {
        return Err(ReadModifyError::InvalidSchema);
    }
    let matched_dn_len = read_length(&mut r)?;
    let mut matched_dn = vec![0; matched_dn_len];
    r.read_exact(&mut matched_dn)?;
    let Ok(_) = String::from_utf8(matched_dn) else {
        return Err(ReadModifyError::InvalidSchema);
    };

    let diagnostics_tag = r.read_single_byte()?;
    if diagnostics_tag != OCTET_STRING {
        return Err(ReadModifyError::InvalidSchema);
    }
    let diagnostics_len = read_length(&mut r)?;
    let mut message = vec![0; diagnostics_len];
    r.read_exact(&mut message)?;
    let diagnostics_message = String::from_utf8_lossy(&message).to_string();
    Err(ReadModifyError::ServerError {
        code,
        message: diagnostics_message,
    })
}

#[derive(Debug)]
pub(crate) enum ReadModifyError {
    InvalidSchema,
    Io(std::io::Error),
    ServerError { code: ResultCode, message: String },
}
impl From<std::io::Error> for ReadModifyError {
    fn from(value: std::io::Error) -> Self {
        Self::Io(value)
    }
}
impl From<LengthError> for ReadModifyError {
    fn from(value: LengthError) -> Self {
        match value {
            LengthError::Io(error) => Self::Io(error),
            LengthError::Unbounded | LengthError::OutOfRange => Self::InvalidSchema,
        }
    }
}
impl From<ReadIntegerError> for ReadModifyError {
    fn from(value: ReadIntegerError) -> Self {
        match value {
            ReadIntegerError::Io(error) => Self::Io(error),
            ReadIntegerError::Length(_) | ReadIntegerError::OutOfRange => Self::InvalidSchema,
        }
    }
}
