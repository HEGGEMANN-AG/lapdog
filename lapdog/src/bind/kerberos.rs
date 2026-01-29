use cross_krb5::{ClientCtx, InitiateFlags, K5Ctx, PendingClientCtx, Step};
use rasn_ldap::{AuthenticationChoice, BindRequest, BindResponse, ProtocolOp, ResultCode, SaslCredentials};
#[cfg(feature = "rustls")]
use rustls::ClientConnection;
use std::{
    convert::Infallible,
    io::{Read, Write},
    ops::Deref,
};

use crate::{LdapConnection, MessageError, bind::impl_bound};

impl_bound!(BoundKerberos);

/// Markers for allowing channel binding an requiring an extra security layer
/// This is extra data required for Kerberos functionality
pub trait LdapStream: Read + Write {
    type Err;
    type OutputStream;
    fn to_output_stream(self, client_context: ClientCtx, max_buffer_size: usize) -> Self::OutputStream;
    fn channel_bindings(&self) -> Result<Option<Vec<u8>>, Self::Err> {
        Ok(None::<Vec<u8>>)
    }
    fn needs_security_layer() -> bool {
        true
    }
}
impl LdapStream for std::net::TcpStream {
    type Err = Infallible;
    type OutputStream = KerberosEncryptedStream<Self>;
    fn to_output_stream(self, client_context: ClientCtx, max_buffer_size: usize) -> Self::OutputStream {
        KerberosEncryptedStream::new(self, client_context, max_buffer_size)
    }
}

#[cfg(feature = "native-tls")]
impl<S: Read + Write> LdapStream for native_tls::TlsStream<S> {
    type Err = native_tls::Error;
    type OutputStream = Self;
    fn to_output_stream(self, _client_context: ClientCtx, _: usize) -> Self::OutputStream {
        self
    }
    fn channel_bindings(&self) -> Result<Option<Vec<u8>>, Self::Err> {
        self.tls_server_end_point()
    }
    fn needs_security_layer() -> bool {
        false
    }
}
#[cfg(feature = "rustls")]
impl<S: Read + Write> LdapStream for rustls::StreamOwned<ClientConnection, S> {
    type Err = Infallible;
    type OutputStream = Self;
    fn to_output_stream(self, _client_context: ClientCtx, _: usize) -> Self::OutputStream {
        self
    }
    fn channel_bindings(&self) -> Result<Option<Vec<u8>>, Self::Err> {
        match self.conn.peer_certificates() {
            None | Some([]) => Ok(None),
            Some([first, ..]) => {
                use sha2::Digest;
                use std::fmt::Write;
                let mut hasher = sha2::Sha256::new();
                hasher.update(first.as_ref());
                let hash = hasher.finalize().to_vec();
                let mut output = String::with_capacity(85);
                output.push_str("tls-server-end-point:");
                for num in hash {
                    write!(output, "{num:x}").expect("Writing to string");
                }
                dbg!(output.capacity(), output.len());
                Ok(Some(output.into()))
            }
        }
    }
    fn needs_security_layer() -> bool {
        false
    }
}

const MUTUAL_AUTH: u32 = 0x2;
const REPLAY_PROT: u32 = 0x4;
const SEQUENCE: u32 = 0x8;
const CONFIDENTIALITY: u32 = 0x10;
const INTEGRITY: u32 = 0x20;
impl<Stream: LdapStream, B> LdapConnection<Stream, B>
where
    Stream::OutputStream: Read + Write,
{
    pub fn bind_kerberos_with_creds(
        self,
        service_principal: &str,
        cred: cross_krb5::Cred,
        max_buffer_size: Option<usize>,
    ) -> Result<LdapConnection<Stream::OutputStream, BoundKerberos>, BindKerberosError<Stream::Err>> {
        let (ctx, initial_token) = ClientCtx::new_with_cred(
            cred,
            service_principal,
            self.stream
                .channel_bindings()
                .map_err(BindKerberosError::FailedToGetChannelBindings)?
                .as_ref()
                .map(|x| x.as_ref()),
        )
        .map_err(|anyhow_error| BindKerberosError::InitializeSecurityContext(anyhow_error.into_boxed_dyn_error()))?;
        self.bind_kerberos_with_ctx(ctx, initial_token, max_buffer_size)
    }

    fn bind_kerberos_with_ctx(
        mut self,
        mut ctx: PendingClientCtx,
        initial_token: impl Deref<Target = [u8]>,
        max_buffer_size: Option<usize>,
    ) -> Result<LdapConnection<Stream::OutputStream, BoundKerberos>, BindKerberosError<Stream::Err>> {
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
                Step::Finished((kerberos, ticket)) => {
                    return self.negotiate_security(kerberos, ticket, max_buffer_size);
                }
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
    pub fn bind_kerberos(
        self,
        service_principal: &str,
        max_buffer_size: Option<usize>,
    ) -> Result<LdapConnection<Stream::OutputStream, BoundKerberos>, BindKerberosError<Stream::Err>> {
        let (ctx, initial_token) = ClientCtx::new(
            InitiateFlags::from_bits_retain(MUTUAL_AUTH | REPLAY_PROT | SEQUENCE | CONFIDENTIALITY | INTEGRITY),
            None,
            service_principal,
            self.stream
                .channel_bindings()
                .map_err(BindKerberosError::FailedToGetChannelBindings)?
                .as_ref()
                .map(|x| x.as_ref()),
        )
        .map_err(|anyhow_error| BindKerberosError::InitializeSecurityContext(anyhow_error.into_boxed_dyn_error()))?;
        self.bind_kerberos_with_ctx(ctx, initial_token, max_buffer_size)
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
        own_max_buffer_size: Option<usize>,
    ) -> Result<LdapConnection<Stream::OutputStream, BoundKerberos>, BindKerberosError<Stream::Err>> {
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
        let own_buffer_size = own_max_buffer_size.unwrap_or(65535);
        let negotiated_buffer_size = (max_buffer_size as usize).min(own_buffer_size);
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
        let response_packet = (layer_response as u32) << 24 | (negotiated_buffer_size as u32);
        let size_msg = kerberos_context
            .wrap(true, &response_packet.to_be_bytes())
            .map_err(|e| BindKerberosError::FailedToEncryptNegotiationData(e.into_boxed_dyn_error()))?;
        match self.send_kerberos_token_msg(&size_msg)? {
            BindResponse {
                result_code: ResultCode::Success,
                diagnostic_message,
                ..
            } => Ok(LdapConnection {
                stream: self.stream.to_output_stream(kerberos_context, negotiated_buffer_size),
                next_message_id: self.next_message_id,
                state: BoundKerberos::new(diagnostic_message.0.into_boxed_str()),
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

pub struct KerberosEncryptedStream<S> {
    stream: S,
    client_context: ClientCtx,
    buffer: Vec<u8>,
    max_buffer_size: usize,
}
impl<S> KerberosEncryptedStream<S> {
    fn new(stream: S, client_context: ClientCtx, max_buffer_size: usize) -> Self {
        Self {
            stream,
            client_context,
            max_buffer_size,
            buffer: Vec::new(),
        }
    }
}
impl<S: Read> Read for KerberosEncryptedStream<S> {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        if self.buffer.is_empty() {
            let mut len_buf = [0u8; 4];
            let mut total_read = 0;
            while total_read < 4 {
                let read = self.stream.read(&mut len_buf[total_read..])?;
                if read == 0 {
                    return Ok(0);
                }
                total_read += read;
            }
            let token_length = u32::from_be_bytes(len_buf) as usize;

            if token_length == 0 || token_length > self.max_buffer_size {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    format!("Invalid token length: {token_length}"),
                ));
            };

            let mut token = vec![0u8; token_length];
            let mut total_read = 0;
            while total_read < token_length {
                let read = self.stream.read(&mut token[total_read..])?;
                if read == 0 {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::UnexpectedEof,
                        "Incomplete token",
                    ));
                }
                total_read += read;
            }

            let unwrapped = self.client_context.unwrap(&token).map_err(std::io::Error::other)?;
            self.buffer.extend_from_slice(&unwrapped);
        }

        let len = buf.len().min(self.buffer.len());
        buf[..len].copy_from_slice(&self.buffer[..len]);
        self.buffer.drain(..len);
        Ok(len)
    }
}
impl<S: Write> Write for KerberosEncryptedStream<S> {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        let wrapped = self.client_context.wrap(true, buf).map_err(std::io::Error::other)?;
        self.stream.write_all(&(wrapped.len() as u32).to_be_bytes())?;
        self.stream.write_all(&wrapped)?;
        Ok(buf.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        self.stream.flush()
    }
}

#[derive(Debug)]
pub enum BindKerberosError<E = Infallible> {
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
