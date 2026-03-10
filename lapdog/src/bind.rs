use std::io::{Read, Write};

const SASL_CREDS: u8 = TagClass::Universal.into_bits() | PrimOrCons::Primitive.into_bit() | 0x7;
use kenobi::{
    client::{ClientBuilder, StepOut},
    cred::{Credentials, Outbound},
};

use crate::{
    LDAP_VERSION, LdapConnection, ReadExt, ResponseProtocolOp, WriteExt,
    auth::{Authentication, SaslMechanism},
    integer::{INTEGER_BYTE, read_integer_body},
    length::{read_length, write_length},
    message::{ProtocolOp, RequestProtocolOp},
    result::ResultCode,
    tag::{
        OCTET_STRING, PrimitiveOrConstructed as PrimOrCons, TagClass, UNIVERSAL_ENUMERATED,
        get_tag_number,
    },
};

impl LdapConnection {
    #[cfg(feature = "kerberos")]
    /// Technically too strict, as this could also just hold the lock on inflight_requests directly
    pub async fn bind_kerberos(&mut self, cred: &Credentials<Outbound>, spn: Option<&str>) {
        let inflight_requests = self.inflight_requests.lock().await;
        if !inflight_requests.is_empty() {
            panic!("cannot be active requests in flight for bind operations");
        }
        drop(inflight_requests);
        let client_builder = ClientBuilder::new_from_credentials(cred, spn)
            .request_signing()
            .request_encryption();

        // take both streams, join them for the channel binding, give them back
        let (return_envelope, rec_stream_half) = tokio::sync::oneshot::channel();
        let (give_back_stream_half, return_return_envelope) = tokio::sync::oneshot::channel();
        self.yoink_read_half
            .send((return_envelope, return_return_envelope))
            .await
            .unwrap();
        let client_builder = {
            let (mut own_lock, read_half) = tokio::join!(self.tcp.lock(), rec_stream_half);
            use crate::stream::Stream;

            let write = own_lock.take().unwrap();
            let stream = Stream::unsplit(read_half.unwrap(), write);
            let cb = client_builder.bind_to_channel(&stream).unwrap();
            let (r, w) = stream.split();
            *own_lock = Some(w);
            give_back_stream_half.send(r).unwrap();
            cb
        };
        let mut ctx = match client_builder.initialize() {
            StepOut::Pending(pending_client_context) => pending_client_context,
            StepOut::Finished(_) => unreachable!(),
        };
        let finished_ctx = loop {
            let (_m, body) = self
                .send_message(RequestProtocolOp::Bind {
                    authentication: Authentication::sasl_gss(Some(ctx.next_token())),
                })
                .await;
            let ResponseProtocolOp::Bind {
                server_sasl_creds: Some(return_token),
            } = ResponseProtocolOp::read_from(&mut body.as_slice()).unwrap()
            else {
                panic!("Invalid protocol op")
            };
            ctx = match ctx.step(&return_token) {
                StepOut::Pending(pending_client_context) => pending_client_context,
                StepOut::Finished(client_context) => {
                    let Ok(with_signing) = client_context.check_encryption() else {
                        panic!("signing not enabled")
                    };
                    let Ok(with_encryption) = with_signing.check_signing() else {
                        panic!("encryption not enabled");
                    };
                    break with_encryption;
                }
            }
        };
        let (_, body) = self
            .send_message(RequestProtocolOp::Bind {
                authentication: Authentication::sasl_gss(None),
            })
            .await;
        let ResponseProtocolOp::Bind {
            server_sasl_creds: Some(token),
        } = ResponseProtocolOp::read_from(&mut body.as_slice()).unwrap()
        else {
            panic!()
        };
        let token_cleartext = finished_ctx.unwrap(&token).unwrap();
        println!("Unwrapped cleartext");
        let Some(token_cleartext): Option<[u8; 4]> = token_cleartext.as_array().copied() else {
            panic!("Server didn't send 4 bytes");
        };
        let bitmask = token_cleartext[0];
        eprintln!("Bitmask sent in subsequent challenge: {bitmask:04b}");
        let mut buffer = [0; 4];
        buffer[1..].copy_from_slice(&token_cleartext[1..4]);
        let buffer_length = u32::from_be_bytes(buffer);
        eprintln!("Buffer length offered: {buffer_length}");
        todo!()
    }
}

#[derive(Debug)]
pub enum BindError {
    Io(std::io::Error),
}

pub fn write_bind(auth: &Authentication) -> std::io::Result<Vec<u8>> {
    let mut bind_msg = Vec::new();
    // version
    bind_msg.write_single_byte(INTEGER_BYTE)?;
    write_length(&mut bind_msg, 1)?;
    bind_msg.write_ber_integer(LDAP_VERSION)?;

    // name
    bind_msg.write_single_byte(
        TagClass::Universal.into_bits() | PrimOrCons::Primitive.into_bit() | 0x04,
    )?;
    write_length(&mut bind_msg, 0)?;

    // authentication
    let Authentication::Sasl {
        mechanism,
        credentials,
    } = auth;
    bind_msg.write_single_byte(
        TagClass::ContextSpecific.into_bits() | PrimOrCons::Constructed.into_bit() | 0x3,
    )?;
    let mut sasl = Vec::new();
    sasl.write_single_byte(OCTET_STRING)?;
    let mech = match mechanism {
        SaslMechanism::GssAPI => "GSSAPI",
    };
    write_length(&mut sasl, mech.len())?;
    sasl.write_all(mech.as_bytes())?;
    if let Some(cred) = credentials {
        sasl.write_single_byte(
            TagClass::Universal.into_bits() | PrimOrCons::Primitive.into_bit() | 0x04,
        )?;
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
