use std::io::{Read, Write};

const SASL_CREDS: u8 = TagClass::Universal.into_bits() | PrimOrCons::Primitive.into_bit() | 0x7;
#[cfg(feature = "kerberos")]
use kenobi::{
    client::ClientBuilder,
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
        OCTET_STRING, PrimitiveOrConstructed as PrimOrCons, TagClass, UNIVERSAL_ENUMERATED, get_tag_number,
    },
};

#[cfg(feature = "kerberos")]
mod kerberos;

impl LdapConnection {
    #[cfg(feature = "kerberos")]
    pub async fn bind_kerberos(
        &mut self,
        cred: &Credentials<Outbound>,
        spn: Option<&str>,
    ) -> Result<(), BindError> {
        self.bind_gss(cred, SaslMechanism::GSSAPI, spn).await
    }
    #[cfg(feature = "kerberos")]
    pub async fn bind_negotiate(
        &mut self,
        cred: &Credentials<Outbound>,
        spn: Option<&str>,
    ) -> Result<(), BindError> {
        self.bind_gss(cred, SaslMechanism::GSSSPNEGO, spn).await
    }
    #[cfg(feature = "kerberos")]
    /// Technically too strict, as this could also just hold the lock on inflight_requests directly
    async fn bind_gss(
        &mut self,
        cred: &Credentials<Outbound>,
        mechanism: SaslMechanism,
        spn: Option<&str>,
    ) -> Result<(), BindError> {
        use std::borrow::Cow;

        use kenobi::client::StepOut;

        let inflight_requests = self.inflight_requests.lock().await;
        if !inflight_requests.is_empty() {
            panic!("cannot be active requests in flight for bind operations");
        }
        drop(inflight_requests);
        // take both streams, join them for the channel binding, give them back
        let (return_envelope, rec_stream_half) = tokio::sync::oneshot::channel();
        let (give_back_stream_half, return_return_envelope) = tokio::sync::oneshot::channel();
        self.yoink_read_half
            .send((return_envelope, return_return_envelope))
            .await
            .unwrap();
        let (client_builder, is_tls) = {
            let (mut own_lock, read_half) = tokio::join!(self.tcp.lock(), rec_stream_half);
            use crate::stream::{Stream, StreamPart};

            let write = own_lock.take().unwrap();
            let is_tls = write.is_tls();
            let client_builder = if is_tls {
                ClientBuilder::new_from_credentials(cred, spn)
            } else {
                ClientBuilder::new_from_credentials(cred, spn)
                    .request_signing()
                    .request_encryption()
            };
            let stream = Stream::unsplit(read_half.unwrap(), write);
            let cb = client_builder.bind_to_channel(&stream).unwrap();
            let (r, w) = stream.split();
            *own_lock = Some(w);
            give_back_stream_half.send(r).unwrap();
            (cb, is_tls)
        };
        let mut ctx = match client_builder.initialize() {
            StepOut::Pending(pending_client_context) => pending_client_context,
            StepOut::Finished(_) => return Ok(()),
        };
        let finished_ctx = loop {
            use std::borrow::Cow;

            let (_m, body) = self
                .send_message(RequestProtocolOp::Bind {
                    authentication: Authentication::Sasl {
                        mechanism,
                        credentials: Some(Cow::Borrowed(ctx.next_token())),
                    },
                })
                .await;
            let ResponseProtocolOp::Bind {
                server_sasl_creds: Some(return_token),
                status,
            } = ResponseProtocolOp::read_from(&mut body.as_slice()).map_err(BindError::Io)?
            else {
                panic!("Invalid protocol op")
            };
            ctx = match status {
                BindStatus::Finished => return Ok(()),
                BindStatus::Pending => match ctx.step(&return_token) {
                    StepOut::Pending(pending_client_context) => pending_client_context,
                    StepOut::Finished(client_context) => {
                        let Some(validated) = kerberos::ValidatedContext::validate(client_context, is_tls)
                        else {
                            return Err(BindError::InvalidSecurityContext);
                        };
                        break validated;
                    }
                },
            }
        };
        assert!(finished_ctx.last_token().is_none());
        let (_, body) = self
            .send_message(RequestProtocolOp::Bind {
                authentication: Authentication::Sasl {
                    mechanism,
                    credentials: None,
                },
            })
            .await;
        let ResponseProtocolOp::Bind {
            server_sasl_creds: Some(token),
            status,
        } = ResponseProtocolOp::read_from(&mut body.as_slice()).unwrap()
        else {
            panic!()
        };
        drop(body);
        let kerberos::ValidatedContext::Kerberos(finished_ctx) = finished_ctx else {
            if status == BindStatus::Finished {
                return Ok(());
            } else {
                panic!("required last contact but doesn't support TLS double encryption")
            }
        };
        let token_cleartext = finished_ctx.unwrap(&token).unwrap();
        let Some(token_cleartext): Option<[u8; 4]> = token_cleartext.as_array().copied() else {
            panic!("Server didn't send 4 bytes");
        };
        let Some(bitmask) = BindSecurityOffer::highest_from_bitmask(token_cleartext[0]) else {
            return Err(BindError::InvalidServerToken);
        };
        eprintln!("Bitmask sent in subsequent challenge: {bitmask:?}");
        let mut buffer = [0; 4];
        buffer[1..].copy_from_slice(&token_cleartext[1..4]);
        let buffer_length = u32::from_be_bytes(buffer);
        eprintln!("Buffer length offered: {buffer_length}");
        buffer[0] = if is_tls { 0x01 } else { 0x4 };
        let wrapped = finished_ctx.sign(&buffer).unwrap();
        let (_id, last_body) = self
            .send_message(RequestProtocolOp::Bind {
                authentication: Authentication::Sasl {
                    mechanism,
                    credentials: Some(Cow::Borrowed(wrapped.as_slice())),
                },
            })
            .await;
        let ResponseProtocolOp::Bind {
            server_sasl_creds,
            status,
        } = ResponseProtocolOp::read_from(&mut last_body.as_slice()).unwrap()
        else {
            panic!()
        };
        dbg!(server_sasl_creds, status);
        todo!()
    }
}

#[derive(Clone, Copy, Debug, Default)]
enum BindSecurityOffer {
    #[default]
    None,
    Signing,
    Encryption,
}
impl BindSecurityOffer {
    fn highest_from_bitmask(b: u8) -> Option<Self> {
        if b & 0x04 != 0 {
            Some(Self::Encryption)
        } else if b & 0x02 != 0 {
            Some(Self::Signing)
        } else if b & 0x01 != 0 {
            Some(Self::None)
        } else {
            None
        }
    }
}

#[derive(Debug)]
#[cfg(feature = "kerberos")]
pub enum BindError {
    Io(std::io::Error),
    InvalidSecurityContext,
    InvalidServerToken,
}

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
        SaslMechanism::GSSAPI => "GSSAPI",
        SaslMechanism::GSSSPNEGO => "GSS-SPNEGO",
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
    let bind_status = match enum_int {
        ResultCode::Success => Ok(BindStatus::Finished),
        ResultCode::SaslBindInProgress => Ok(BindStatus::Pending),
        c => Err(c),
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
    let bind_status = match bind_status {
        Ok(b) => b,
        Err(code) => panic!("Error returned error: {code:?} (\"{diagnostics_message}\")"),
    };

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
        bind_status,
        sasl_creds,
        diagnostics_message,
        matched_dn,
    })
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
