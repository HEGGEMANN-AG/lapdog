use std::io::{Read, Write};

const SASL_CREDS: u8 = TagClass::Universal.into_bits() | PrimOrCons::Primitive.into_bit() | 0x7;
use crate::{
    LDAP_VERSION, ReadExt, WriteExt,
    auth::{Authentication, SaslMechanism},
    integer::{INTEGER_BYTE, read_integer_body},
    length::{read_length, write_length},
    result::ResultCode,
    tag::{OCTET_STRING, PrimitiveOrConstructed as PrimOrCons, TagClass, UNIVERSAL_ENUMERATED, get_tag_number},
};

pub fn write_bind(auth: &Authentication) -> std::io::Result<Vec<u8>> {
    let mut bind_msg = Vec::new();
    // version
    bind_msg.write_single_byte(INTEGER_BYTE)?;
    write_length(&mut bind_msg, 1)?;
    bind_msg.write_ber_integer(LDAP_VERSION)?;

    // name
    bind_msg.write_single_byte(TagClass::Universal.into_bits() | PrimOrCons::Primitive.into_bit() | 0x04)?;
    write_length(&mut bind_msg, 0)?;

    // authentication
    let Authentication::Sasl { mechanism, credentials } = auth;
    bind_msg.write_single_byte(TagClass::ContextSpecific.into_bits() | PrimOrCons::Constructed.into_bit() | 0x3)?;
    let mut sasl = Vec::new();
    sasl.write_single_byte(OCTET_STRING)?;
    let mech = match mechanism {
        SaslMechanism::GssAPI => "GSSAPI",
    };
    write_length(&mut sasl, mech.len())?;
    sasl.write_all(mech.as_bytes())?;
    if let Some(cred) = credentials {
        sasl.write_single_byte(TagClass::Universal.into_bits() | PrimOrCons::Primitive.into_bit() | 0x04)?;
        write_length(&mut sasl, cred.len())?;
        sasl.write_all(cred)?;
    }

    write_length(&mut bind_msg, sasl.len())?;
    bind_msg.write_all(&sasl)?;
    Ok(bind_msg)
}

pub fn read_response<R: Read>(mut r: R) -> std::io::Result<BindResponse> {
    let tag = r.read_single_byte()?;
    if tag != UNIVERSAL_ENUMERATED {
        panic!("Invalid schema")
    }
    // LdapResult code
    let enum_int = {
        let enum_len = read_length(&mut r)?.unwrap();
        let mut enum_i = vec![0; enum_len];
        r.read_exact(&mut enum_i)?;
        read_integer_body(&enum_i)
            .unwrap()
            .try_into()
            .ok()
            .and_then(ResultCode::from_code)
            .unwrap()
    };
    let ResultCode::SaslBindInProgress = enum_int else {
        panic!("weird response code");
    };

    let matched_dn_tag = r.read_single_byte()?;
    if matched_dn_tag != OCTET_STRING {
        panic!("Invalid matched DN string");
    }
    let matched_dn_len = read_length(&mut r)?.unwrap();
    let mut matched_dn = vec![0; matched_dn_len];
    r.read_exact(&mut matched_dn)?;
    let Ok(matched_dn) = String::from_utf8(matched_dn) else {
        panic!("non-utf8 matched DN")
    };

    let diagnostics_tag = r.read_single_byte()?;
    if diagnostics_tag != OCTET_STRING {
        panic!("Invalid diagnostics message");
    }
    let diagnostics_len = read_length(&mut r)?.unwrap();
    let mut diagnostics_message = vec![0; diagnostics_len];
    r.read_exact(&mut diagnostics_message)?;
    let diagnostics_message = String::from_utf8_lossy(&diagnostics_message).to_string();

    let referral_or_sasl_tag = r.read_single_byte()?;
    let sasl_creds = match get_tag_number(referral_or_sasl_tag) {
        0x3 => panic!("unexpected referral"),
        SASL_CREDS => {
            let sasl_len = read_length(&mut r)?.unwrap();
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
        sasl_creds,
        diagnostics_message,
        matched_dn,
    })
}

pub struct BindResponse {
    pub sasl_creds: Option<Vec<u8>>,
    pub diagnostics_message: String,
    pub matched_dn: String,
}
