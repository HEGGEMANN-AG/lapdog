use std::io::{Read, Write};

use cross_krb5::{ClientCtx, InitiateFlags, K5Ctx, Step};
use rasn_ldap::{AuthenticationChoice, BindRequest, BindResponse, ProtocolOp, ResultCode, SaslCredentials};

use crate::{LdapConnection, MessageError};

pub struct BoundKerberos {
    _priv: (),
}

// Markers for allowing channel binding an requiring an extra security layer
pub trait LdapStream: Read + Write {
    type Err;
    fn channel_bindings(&self) -> Result<Option<Vec<u8>>, Self::Err> {
        Ok(None::<Vec<u8>>)
    }
    fn needs_security_layer() -> bool {
        true
    }
}
impl LdapStream for std::net::TcpStream {
    type Err = std::convert::Infallible;
}

#[cfg(feature = "native-tls")]
impl<S: Read + Write> LdapStream for native_tls::TlsStream<S> {
    type Err = native_tls::Error;
    fn channel_bindings(&self) -> Result<Option<Vec<u8>>, Self::Err> {
        self.tls_server_end_point()
    }
    fn needs_security_layer() -> bool {
        false
    }
}

impl<Stream: LdapStream, B> LdapConnection<Stream, B> {
    pub fn bind_kerberos(
        mut self,
        service_principal: &str,
    ) -> Result<LdapConnection<Stream, BoundKerberos>, BindKerberosError<Stream::Err>> {
        let (mut ctx, initial_token) = ClientCtx::new(
            InitiateFlags::from_bits_retain(0x2 | 0x4 | 0x8 | 0x10 | 0x20),
            None,
            service_principal,
            self.stream
                .channel_bindings()
                .map_err(BindKerberosError::FailedToGetChannelBindings)?
                .as_ref()
                .map(|x| x.as_ref()),
        )
        .map_err(|anyhow_error| BindKerberosError::InitializeSecurityContext(anyhow_error.into_boxed_dyn_error()))?;
        let BindResponse {
            result_code,
            server_sasl_creds,
            diagnostic_message,
            ..
        } = self.send_kerberos_token_msg(&initial_token)?;
        if result_code != ResultCode::SaslBindInProgress {
            return Err(BindKerberosError::DidntAcceptBind(
                result_code,
                diagnostic_message.as_str().into(),
            ));
        }
        let mut msg: Vec<u8> = server_sasl_creds
            .ok_or(BindKerberosError::ServerSentNoCredentials)?
            .to_vec();
        debug_assert!(!msg.is_empty());
        loop {
            ctx = match ctx.step(&msg).map_err(|anyhow_error| {
                BindKerberosError::InitializeSecurityContext(anyhow_error.into_boxed_dyn_error())
            })? {
                Step::Finished((kerberos, ticket)) => return self.negotiate_security(kerberos, ticket),
                Step::Continue((pending, ticket)) => {
                    let BindResponse { server_sasl_creds, .. } = self.send_kerberos_token_msg(&ticket)?;
                    msg = server_sasl_creds
                        .ok_or(BindKerberosError::ServerSentNoCredentials)?
                        .to_vec();
                    pending
                }
            }
        }
    }
    fn send_kerberos_token_msg<E>(&mut self, token: &[u8]) -> Result<BindResponse, BindKerberosError<E>> {
        let sasl = SaslCredentials::new("GSSAPI".into(), Some(token.to_vec().into()));
        let message = BindRequest::new(3, "".into(), AuthenticationChoice::Sasl(sasl));
        let op = ProtocolOp::BindRequest(message);
        match self.send_single_message(op, None) {
            Ok(ProtocolOp::BindResponse(b)) => Ok(b),
            Ok(_) => Err(BindKerberosError::InvalidMessage),
            Err(MessageError::UnsolicitedResponse) => Err(BindKerberosError::InvalidMessage),
            Err(MessageError::Io(io)) => Err(BindKerberosError::Io(io)),
            Err(MessageError::Message(dec)) => Err(BindKerberosError::Decode(dec)),
        }
    }
    fn negotiate_security(
        mut self,
        mut kerberos_context: ClientCtx,
        last_token: Option<impl std::ops::Deref<Target = [u8]>>,
    ) -> Result<LdapConnection<Stream, BoundKerberos>, BindKerberosError<Stream::Err>> {
        let BindResponse { server_sasl_creds, .. } =
            self.send_kerberos_token_msg(last_token.as_deref().unwrap_or_default())?;
        let bytes = kerberos_context
            .unwrap(&server_sasl_creds.ok_or(BindKerberosError::ServerSentInvalidNegotiationData)?)
            .map_err(|e| BindKerberosError::FailedToDecryptNegotiationData(e.into_boxed_dyn_error()))?;
        let Ok([offer_bitmask, x, y, z]) = <[u8; 4]>::try_from(bytes.as_ref()) else {
            return Err(BindKerberosError::ServerSentInvalidNegotiationData);
        };
        let max_buffer_size = u32::from_be_bytes([0, x, y, z]);
        if offer_bitmask == 0 && max_buffer_size != 0 {
            return Err(BindKerberosError::NonzeroBufferSize);
        }
        const NO_SECURITY: u8 = 0x01;
        const CONFIDENTIALITY: u8 = 0x04;
        let layer_response = if Stream::needs_security_layer() {
            CONFIDENTIALITY
        } else {
            NO_SECURITY
        };
        if offer_bitmask | layer_response == 0 {
            return Err(BindKerberosError::NoValidSecurityLayerOffered);
        }
        // See fallback in ldap3
        let response_packet = (layer_response as u32) << 24 | 0x9FFFB8u32;
        let size_msg = kerberos_context
            .wrap(true, &response_packet.to_be_bytes())
            .map_err(|e| BindKerberosError::FailedToEncryptNegotiationData(e.into_boxed_dyn_error()))?;
        match self.send_kerberos_token_msg(&size_msg)? {
            BindResponse {
                result_code: ResultCode::Success,
                ..
            } => Ok(LdapConnection {
                stream: self.stream,
                next_message_id: self.next_message_id,
                state: BoundKerberos { _priv: () },
            }),
            BindResponse {
                result_code,
                diagnostic_message,
                ..
            } => Err(BindKerberosError::DidntAcceptBind(
                result_code,
                diagnostic_message.0.into_boxed_str(),
            )),
        }
    }
}
#[derive(Debug)]
pub enum BindKerberosError<E> {
    InvalidMessage,
    FailedToGetChannelBindings(E),
    ServerSentNoCredentials,
    ServerSentInvalidNegotiationData,
    NoValidSecurityLayerOffered,
    NonzeroBufferSize,
    FailedToDecryptNegotiationData(Box<dyn std::error::Error + 'static>),
    FailedToEncryptNegotiationData(Box<dyn std::error::Error + 'static>),
    InitializeSecurityContext(Box<dyn std::error::Error + 'static>),
    DidntAcceptBind(ResultCode, Box<str>),
    Io(std::io::Error),
    Decode(rasn::ber::de::DecodeError),
}
impl<E: std::error::Error> std::error::Error for BindKerberosError<E> {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Decode(dec) => Some(dec),
            Self::Io(io) => Some(io),
            Self::InitializeSecurityContext(isc)
            | Self::FailedToDecryptNegotiationData(isc)
            | Self::FailedToEncryptNegotiationData(isc) => Some(isc.as_ref()),
            _ => None,
        }
    }
}
impl<E: std::fmt::Display> std::fmt::Display for BindKerberosError<E> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidMessage => write!(f, "Server sent a non-\"bind response\" response"),
            Self::FailedToGetChannelBindings(e) => write!(f, "Failed to get channel bindings: {e}"),
            Self::ServerSentNoCredentials => write!(f, "The server sent no more credentials prematurely"),
            Self::NoValidSecurityLayerOffered => write!(f, "The server didn't offer a necessary security layer"),
            Self::NonzeroBufferSize => write!(f, "Server sent nonzero buffer size without security offers"),
            Self::ServerSentInvalidNegotiationData => write!(f, "Server sent no or invalid negotiation data"),
            Self::FailedToDecryptNegotiationData(e) => write!(f, "Failed to decrypt server negotiation data: {e}"),
            Self::FailedToEncryptNegotiationData(e) => write!(f, "Failed to encrypt client negotiation data: {e}"),
            Self::InitializeSecurityContext(isc) => write!(f, "Kerberos security context error: {isc}"),
            Self::DidntAcceptBind(code, error) => write!(f, "Server didn't accept bind: {code:?} {error}"),
            Self::Io(io) => write!(f, "Failed to write to stream: {io}"),
            Self::Decode(dec) => write!(f, "Failed to decode server response: {dec}"),
        }
    }
}
