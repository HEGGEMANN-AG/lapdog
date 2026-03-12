use std::io::Read;

const SASL_CREDS: u8 = TagClass::Universal.into_bits() | PrimOrCons::Primitive.into_bit() | 0x7;

use crate::{
    LDAP_VERSION, WriteExt,
    auth::{Authentication, SaslMechanism},
    integer::{InvalidI32, read_integer_body},
    length::read_length,
    read::ReadExt,
    result::ResultCode,
    tag::{
        OCTET_STRING, PrimitiveOrConstructed as PrimOrCons, TagClass, UNIVERSAL_ENUMERATED,
        UNIVERSAL_INTEGER, get_tag_number,
    },
};

#[cfg(feature = "kerberos")]
pub mod kerberos;

pub fn write_bind(auth: &Authentication) -> Vec<u8> {
    let mut bind_msg = Vec::new();
    // version
    bind_msg.push(UNIVERSAL_INTEGER);
    bind_msg.write_ber_length(1).expect("infallible");
    bind_msg.write_ber_integer(LDAP_VERSION).expect("infallible");

    // name
    bind_msg.push(TagClass::Universal.into_bits() | PrimOrCons::Primitive.into_bit() | 0x04);
    bind_msg.write_ber_length(0).expect("infallible");

    // authentication
    let Authentication::Sasl {
        mechanism,
        credentials,
    } = auth;
    bind_msg.push(TagClass::ContextSpecific.into_bits() | PrimOrCons::Constructed.into_bit() | 0x3);
    let mut sasl = Vec::new();
    sasl.push(OCTET_STRING);
    let mech = match mechanism {
        SaslMechanism::GSSAPI => "GSSAPI",
        SaslMechanism::GSSSPNEGO => "GSS-SPNEGO",
    };
    sasl.write_ber_length(mech.len()).expect("infallible");
    sasl.extend(mech.as_bytes());
    if let Some(cred) = credentials {
        sasl.push(TagClass::Universal.into_bits() | PrimOrCons::Primitive.into_bit() | 0x04);
        sasl.write_ber_length(cred.len()).expect("infallible");
        sasl.extend_from_slice(cred);
    }

    bind_msg.write_ber_length(sasl.len()).expect("infallible");
    bind_msg.extend_from_slice(&sasl);
    bind_msg
}

pub fn read_response<R: Read>(mut r: R) -> Result<BindResponse, ReadBindError> {
    let tag = r.read_single_byte()?;
    if tag != UNIVERSAL_ENUMERATED {
        return Err(ReadBindError::InvalidSchema);
    }
    // LdapResult code
    let enum_int = {
        let enum_len = read_length(&mut r)?.ok_or(ReadBindError::InvalidSchema)?;
        let mut enum_i = vec![0; enum_len];
        r.read_exact(&mut enum_i)?;
        read_integer_body(&enum_i)?
            .try_into()
            .ok()
            .and_then(ResultCode::from_code)
            .ok_or(ReadBindError::InvalidResultCode)?
    };
    let bind_status = match enum_int {
        ResultCode::Success => Ok(BindStatus::Finished),
        ResultCode::SaslBindInProgress => Ok(BindStatus::Pending),
        c => Err(c),
    };

    let matched_dn_tag = r.read_single_byte()?;
    if matched_dn_tag != OCTET_STRING {
        return Err(ReadBindError::InvalidSchema);
    }
    let matched_dn_len = read_length(&mut r)?.ok_or(ReadBindError::InvalidSchema)?;
    let mut matched_dn = vec![0; matched_dn_len];
    r.read_exact(&mut matched_dn)?;
    let Ok(matched_dn) = String::from_utf8(matched_dn) else {
        return Err(ReadBindError::InvalidSchema);
    };

    let diagnostics_tag = r.read_single_byte()?;
    if diagnostics_tag != OCTET_STRING {
        return Err(ReadBindError::InvalidSchema);
    }
    let diagnostics_len = read_length(&mut r)?.ok_or(ReadBindError::InvalidSchema)?;
    let mut diagnostics_message = vec![0; diagnostics_len];
    r.read_exact(&mut diagnostics_message)?;
    let diagnostics_message = String::from_utf8_lossy(&diagnostics_message).to_string();
    let bind_status = bind_status.map_err(|code| ReadBindError::BindError {
        code,
        message: diagnostics_message.clone(),
    })?;

    let referral_or_sasl_tag = r.read_single_byte()?;
    let sasl_creds = match get_tag_number(referral_or_sasl_tag) {
        0x3 => panic!("unexpected referral"),
        SASL_CREDS => {
            let sasl_len = read_length(&mut r)?.ok_or(ReadBindError::InvalidSchema)?;
            if sasl_len == 0 {
                None
            } else {
                let mut sasl_creds = vec![0; sasl_len];
                r.read_exact(&mut sasl_creds)?;
                Some(sasl_creds)
            }
        }
        _ => todo!(),
    };
    Ok(BindResponse {
        bind_status,
        sasl_creds,
        diagnostics_message,
        matched_dn,
    })
}

#[derive(Debug)]
pub enum ReadBindError {
    Io(std::io::Error),
    BindError { code: ResultCode, message: String },
    InvalidResultCode,
    InvalidSchema,
}
impl From<std::io::Error> for ReadBindError {
    fn from(value: std::io::Error) -> Self {
        Self::Io(value)
    }
}
impl From<InvalidI32> for ReadBindError {
    fn from(_: InvalidI32) -> Self {
        Self::InvalidSchema
    }
}

#[derive(Clone, Copy, Debug, PartialEq)]
pub enum BindStatus {
    Finished,
    Pending,
}

#[derive(Debug)]
pub struct BindResponse {
    pub bind_status: BindStatus,
    pub sasl_creds: Option<Vec<u8>>,
    pub diagnostics_message: String,
    pub matched_dn: String,
}
