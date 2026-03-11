use std::{
    io::{Read, Write},
    sync::Arc,
};

const SASL_CREDS: u8 = TagClass::Universal.into_bits() | PrimOrCons::Primitive.into_bit() | 0x7;
#[cfg(feature = "kerberos")]
use kenobi::{
    client::ClientBuilder,
    cred::{Credentials, Outbound},
};
use kenobi::{
    client::ClientContext,
    typestate::{Encryption, MaybeDelegation, Signing},
};
use tokio::sync::{Mutex, mpsc, oneshot};

use crate::{
    LDAP_VERSION, LdapConnection, ResponseProtocolOp, WriteExt,
    auth::{Authentication, SaslMechanism},
    integer::{INTEGER_BYTE, read_integer_body},
    length::{read_length, write_length},
    message::{ProtocolOp, RequestProtocolOp},
    read::ReadExt,
    result::ResultCode,
    stream::{StreamReadHalf, StreamWriteHalf},
    tag::{
        OCTET_STRING, PrimitiveOrConstructed as PrimOrCons, TagClass, UNIVERSAL_ENUMERATED, get_tag_number,
    },
};

impl LdapConnection {
    #[cfg(feature = "kerberos")]
    pub async fn bind_sasl_kenobi(
        &mut self,
        cred: Credentials<Outbound>,
        spn: Option<&str>,
    ) -> Result<(), BindError> {
        use kenobi::mech::Mechanism;

        let mech = match cred.mechanism() {
            Mechanism::KerberosV5 => SaslMechanism::GSSAPI,
            Mechanism::Spnego => SaslMechanism::GSSSPNEGO,
        };
        if self.is_tls().await {
            #[cfg(feature = "native-tls")]
            return self.bind_gss_tls(cred, mech, spn).await;
            #[cfg(not(feature = "native-tls"))]
            unreachable!()
        } else {
            self.bind_gss(cred, mech, spn).await
        }
    }
    #[cfg(all(feature = "kerberos", feature = "native-tls"))]
    async fn bind_gss_tls(
        &mut self,
        cred: Credentials<Outbound>,
        mechanism: SaslMechanism,
        spn: Option<&str>,
    ) -> Result<(), BindError> {
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
        let client_builder = {
            let (mut own_lock, read_half) = tokio::join!(self.tcp.lock(), rec_stream_half);
            use crate::stream::Stream;
            let write = own_lock.take().unwrap();
            let stream = Stream::unsplit(read_half.unwrap(), write);
            let client_builder = ClientBuilder::new_from_credentials(cred, spn)
                .offer_mutual_auth()
                .request_delegation()
                .bind_to_channel(&stream)
                .unwrap();
            let (r, w) = stream.split();
            *own_lock = Some(w);
            if give_back_stream_half.send(r).is_err() {
                panic!("read half was dropped before we could give it back to the main loop")
            };
            client_builder
        };
        match client_builder.initialize() {
            StepOut::Finished(f) => {
                println!(
                    "Kerberos mechanism finished without any steps, likely because the credentials were already valid for the server"
                );
                let Some(token) = f.last_token() else {
                    panic!("Kerberos mechanism didn't return a token on the first step, but it should have")
                };
                let (_, body) = self
                    .send_message(RequestProtocolOp::Bind {
                        authentication: Authentication::Sasl {
                            mechanism,
                            credentials: Some(token.into()),
                        },
                    })
                    .await
                    .unwrap();
                let ResponseProtocolOp::Bind {
                    server_sasl_creds: Some(token),
                    status,
                } = ResponseProtocolOp::read_from(&mut body.as_slice()).unwrap()
                else {
                    panic!()
                };
                dbg!(status, token);
                todo!()
            }
            StepOut::Pending(mut ctx) => loop {
                use std::borrow::Cow;
                let (_m, body) = self
                    .send_message(RequestProtocolOp::Bind {
                        authentication: Authentication::Sasl {
                            mechanism,
                            credentials: Some(Cow::Borrowed(ctx.next_token())),
                        },
                    })
                    .await
                    .unwrap();
                let ResponseProtocolOp::Bind {
                    server_sasl_creds: Some(return_token),
                    status,
                } = ResponseProtocolOp::read_from(&mut body.as_slice()).map_err(BindError::Io)?
                else {
                    panic!("Invalid protocol op")
                };
                if status == BindStatus::Finished {
                    println!("Server-side authentication finished")
                }
                ctx = match ctx.step(&return_token) {
                    StepOut::Pending(pending_client_context) => pending_client_context,
                    StepOut::Finished(_) => return Ok(()),
                }
            },
        }
    }

    #[cfg(feature = "kerberos")]
    /// Technically too strict, as this could also just hold the lock on inflight_requests directly
    async fn bind_gss(
        &mut self,
        cred: Credentials<Outbound>,
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
        let client_builder = ClientBuilder::new_from_credentials(cred, spn)
            .offer_mutual_auth()
            .request_signing()
            .request_encryption()
            .request_delegation();
        let finished_ctx = match client_builder.initialize() {
            StepOut::Finished(_) => {
                unreachable!(
                    "Kerberos mechanism finished without any steps, but we didn't do a GSSAPI bind with TLS, so this shouldn't be possible"
                )
            }
            StepOut::Pending(mut ctx) => loop {
                use std::borrow::Cow;
                let (_m, body) = self
                    .send_message(RequestProtocolOp::Bind {
                        authentication: Authentication::Sasl {
                            mechanism,
                            credentials: Some(Cow::Borrowed(ctx.next_token())),
                        },
                    })
                    .await
                    .unwrap();
                let ResponseProtocolOp::Bind {
                    server_sasl_creds: Some(return_token),
                    status,
                } = ResponseProtocolOp::read_from(&mut body.as_slice()).map_err(BindError::Io)?
                else {
                    panic!("Invalid protocol op")
                };
                if status == BindStatus::Finished {
                    println!("Server-side authentication finished")
                }
                ctx = match ctx.step(&return_token) {
                    StepOut::Pending(pending_client_context) => pending_client_context,
                    StepOut::Finished(client_context) => {
                        break client_context
                            .check_signing()
                            .ok()
                            .and_then(|c| c.check_encryption().ok())
                            .ok_or(BindError::InvalidSecurityContext)?;
                    }
                }
            },
        };
        println!("Sending empty response");
        let (_, body) = self
            .send_message(RequestProtocolOp::Bind {
                authentication: Authentication::Sasl {
                    mechanism,
                    credentials: None,
                },
            })
            .await
            .unwrap();
        let ResponseProtocolOp::Bind {
            server_sasl_creds: Some(token),
            status,
        } = ResponseProtocolOp::read_from(&mut body.as_slice()).unwrap()
        else {
            panic!()
        };
        dbg!(status);
        drop(body);
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
        buffer[0] = 0x4;
        let wrapped = finished_ctx.sign(&buffer).unwrap();
        let (_id, last_body) = self
            .send_message(RequestProtocolOp::Bind {
                authentication: Authentication::Sasl {
                    mechanism,
                    credentials: Some(Cow::Borrowed(wrapped.as_slice())),
                },
            })
            .await
            .unwrap();
        let ResponseProtocolOp::Bind {
            server_sasl_creds,
            status,
        } = ResponseProtocolOp::read_from(&mut last_body.as_slice()).unwrap()
        else {
            panic!()
        };
        replace_streams_with_kerberos(&mut self.yoink_read_half, &self.tcp, Arc::new(finished_ctx)).await;
        assert!(
            server_sasl_creds.is_none(),
            "Server should not have sent a token in the final step"
        );
        if status == BindStatus::Finished {
            Ok(())
        } else {
            panic!("Server should have finished after the final step")
        }
    }
}

async fn replace_streams_with_kerberos(
    yoink_read_half: &mut mpsc::Sender<(oneshot::Sender<StreamReadHalf>, oneshot::Receiver<StreamReadHalf>)>,
    own_stream: &Mutex<Option<StreamWriteHalf>>,
    client_ctx: Arc<ClientContext<Outbound, Signing, Encryption, MaybeDelegation>>,
) {
    println!("Replacing underlying stream");
    // take both streams, join them for the channel binding, give them back
    let (return_envelope, rec_stream_half) = tokio::sync::oneshot::channel();
    let (give_back_stream_half, return_return_envelope) = tokio::sync::oneshot::channel();
    yoink_read_half
        .send((return_envelope, return_return_envelope))
        .await
        .unwrap();
    let (mut own_lock, read_half) = tokio::join!(own_stream.lock(), rec_stream_half);
    use crate::stream::Stream;

    let write = own_lock.take().unwrap();
    let mut stream = Stream::unsplit(read_half.unwrap(), write);
    if let Stream::Plain(tcp) = stream {
        stream = Stream::Kerberos(client_ctx, tcp)
    }
    let (r, w) = stream.split();
    *own_lock = Some(w);
    if give_back_stream_half.send(r).is_err() {
        panic!("read half was dropped before we could give it back to the main loop")
    };
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
