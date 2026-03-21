use std::{ops::Deref, sync::Arc};

use kenobi::{
    client::{ClientBuilder, ClientContext, StepOut},
    cred::{Credentials, Outbound},
    sign_encrypt::{Signature, UnwrapError, WrapError},
    typestate::{Encryption, MaybeDelegation, MaybeEncryption, MaybeSigning, NoEncryption, Signing},
};
use tokio::sync::{Mutex, mpsc, oneshot};

use crate::{
    LdapConnection, RequestProtocolOp, ResponseProtocolOp, SendMessageError, StreamWriteHalf,
    auth::{Authentication, SaslMechanism},
    bind::BindStatus,
    message::{ProtocolOp, ReadProtocolOpError},
    result::ResultCode,
    stream::StreamReadHalf,
};

fn get_context_builder(
    cred: Credentials<Outbound>,
    target_principal: Option<&str>,
    mech: SaslMechanism,
    is_tls: bool,
) -> ClientBuilder<Outbound> {
    let b = ClientBuilder::new_from_credentials(cred, target_principal).request_mutual_auth();
    match (mech, is_tls) {
        (SaslMechanism::GSSSPNEGO, true) => b,
        (SaslMechanism::GSSAPI, true) => b.request_signing().request_delegation().request_encryption(),
        (SaslMechanism::GSSAPI, false) => b.request_signing().request_encryption().request_delegation(),
        (SaslMechanism::GSSSPNEGO, false) => b.request_signing().request_encryption(),
    }
}

pub(crate) struct MaybeEncryptClientContext {
    kind: InnerContext,
    sign_only: bool,
}
enum InnerContext {
    SignOnly(ClientContext<Outbound, Signing, NoEncryption, MaybeDelegation>),
    CanEncrypt(ClientContext<Outbound, Signing, Encryption, MaybeDelegation>),
}
impl MaybeEncryptClientContext {
    pub fn wrap_best(&self, input: &[u8]) -> Box<dyn Deref<Target = [u8]> + Send> {
        if self.sign_only {
            return Box::new(self.sign(input).unwrap());
        }
        match &self.kind {
            InnerContext::SignOnly(ctx) => Box::new(ctx.sign(input).unwrap()),
            InnerContext::CanEncrypt(ctx) => Box::new(ctx.encrypt(input).unwrap()),
        }
    }
    fn sign(&self, input: &[u8]) -> Result<Signature, WrapError> {
        match &self.kind {
            InnerContext::SignOnly(ctx) => ctx.sign(input),
            InnerContext::CanEncrypt(ctx) => ctx.sign(input),
        }
    }
    pub fn unwrap(&self, input: &[u8]) -> Result<Box<dyn Deref<Target = [u8]>>, UnwrapError> {
        match &self.kind {
            InnerContext::SignOnly(ctx) => ctx
                .unwrap(input)
                .map(|v| Box::new(v) as Box<dyn Deref<Target = [u8]>>),
            InnerContext::CanEncrypt(ctx) => ctx
                .unwrap(input)
                .map(|v| Box::new(v) as Box<dyn Deref<Target = [u8]>>),
        }
    }
}

type FinishedClientContext = ClientContext<Outbound, MaybeSigning, MaybeEncryption, MaybeDelegation>;
impl LdapConnection {
    /// Binds the current connection via Kerberos using the kenobi crate.
    /// The mechanism used depends on the underlying mechanism on the Kenobi credentials handle.
    /// If the connection is already on TLS, channel bindings will be provided.
    /// If the connection is not, it will upgrade to a GSSAPI-wrapped LDAP stream.
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
        let is_tls = match self.tcp.lock().await.as_ref().unwrap() {
            StreamWriteHalf::Plain(_) => false,
            #[cfg(feature = "native-tls")]
            StreamWriteHalf::NativeTls(_) => true,
            StreamWriteHalf::Kerberos(_, _) => panic!("Already bound with Kerberos, cannot bind again"),
        };
        if is_tls {
            #[cfg(feature = "native-tls")]
            return self.bind_gss_tls(cred, mech, spn).await;
            #[cfg(not(feature = "native-tls"))]
            unreachable!()
        } else {
            self.bind_gss(cred, mech, spn).await
        }
    }

    #[cfg(feature = "native-tls")]
    async fn bind_gss_tls(
        &mut self,
        cred: Credentials<Outbound>,
        mechanism: SaslMechanism,
        spn: Option<&str>,
    ) -> Result<(), BindError> {
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
            let client_builder = get_context_builder(cred, spn, mechanism, true).bind_to_channel(&stream);
            let (r, w) = stream.split();
            *own_lock = Some(w);
            if give_back_stream_half.send(r).is_err() {
                panic!("read half was dropped before we could give it back to the main loop")
            };
            client_builder
        };
        let Ok(client_builder) = client_builder else {
            return Err(BindError::ChannelBind);
        };
        let (Some(ctx), status) = self.exchange_gss_tokens(client_builder, mechanism).await? else {
            println!("context not ready after exchange");
            return Err(BindError::InvalidSecurityContext);
        };
        match (mechanism, status) {
            (SaslMechanism::GSSSPNEGO, BindStatus::Finished) => Ok(()),
            (SaslMechanism::GSSAPI, BindStatus::Pending) => {
                let Ok(signing) = ctx.check_signing() else {
                    return Err(BindError::Insecure);
                };
                self.do_kerberos_negotiation_exchange(signing).await?;
                Ok(())
            }
            _ => todo!(),
        }
    }

    /// Technically too strict, as this could also just hold the lock on inflight_requests directly
    async fn bind_gss(
        &mut self,
        cred: Credentials<Outbound>,
        mechanism: SaslMechanism,
        spn: Option<&str>,
    ) -> Result<(), BindError> {
        let inflight_requests = self.inflight_requests.lock().await;
        if !inflight_requests.is_empty() {
            panic!("cannot be active requests in flight for bind operations");
        }
        drop(inflight_requests);
        let client_builder = get_context_builder(cred, spn, mechanism, false);
        let (Some(finished_ctx), server_status) = self.exchange_gss_tokens(client_builder, mechanism).await?
        else {
            return Err(BindError::InvalidSchema);
        };
        match (mechanism, server_status) {
            (SaslMechanism::GSSSPNEGO, BindStatus::Finished) => {
                // Just assume I can encrypt honestly, what the fuck is this behaviour
                let kind = match finished_ctx
                    .check_signing()
                    .map_err(|_| BindError::Insecure)?
                    .check_encryption()
                {
                    Ok(can_encrypt) => InnerContext::CanEncrypt(can_encrypt),
                    Err(sign_only) => InnerContext::SignOnly(sign_only),
                };
                let ctx = MaybeEncryptClientContext {
                    kind,
                    sign_only: false,
                };
                encrypt_stream(&mut self.yoink_read_half, &self.tcp, Arc::new(Mutex::new(ctx))).await;
                Ok(())
            }
            (SaslMechanism::GSSAPI, BindStatus::Pending) => {
                let Ok(signing) = finished_ctx.check_signing() else {
                    return Err(BindError::Insecure);
                };
                let enc_layer = self.do_kerberos_negotiation_exchange(signing).await?;
                encrypt_stream(
                    &mut self.yoink_read_half,
                    &self.tcp,
                    Arc::new(Mutex::new(enc_layer)),
                )
                .await;
                Ok(())
            }
            (_, _) => todo!(),
        }
    }

    /// Does the GSSAPI/SPNEGO token exchange.
    /// If the finished context is `None`, the server didn't provide a token to finish the own security context.
    /// This may be an error, but is also valid if the connection is made through TLS and mutual authentication is already implied
    async fn exchange_gss_tokens(
        &self,
        client_builder: ClientBuilder<Outbound>,
        mechanism: SaslMechanism,
    ) -> Result<(Option<FinishedClientContext>, BindStatus), BindError> {
        match client_builder.initialize() {
            StepOut::Finished(f) => {
                let Some(token) = f.last_token() else {
                    panic!("Kerberos mechanism didn't return a token on the first step, but it should have")
                };
                let body = self
                    .send_message(RequestProtocolOp::Bind {
                        authentication: Authentication::Sasl {
                            mechanism,
                            credentials: Some(token.into()),
                        },
                    })
                    .await?
                    .into_message();
                let ResponseProtocolOp::Bind { status, .. } =
                    ResponseProtocolOp::read_from(&mut body.as_slice())?
                else {
                    return Err(BindError::InvalidSchema);
                };
                Ok((None, status))
            }
            StepOut::Pending(mut ctx) => loop {
                use std::borrow::Cow;
                let body = self
                    .send_message(RequestProtocolOp::Bind {
                        authentication: Authentication::Sasl {
                            mechanism,
                            credentials: Some(Cow::Borrowed(ctx.next_token())),
                        },
                    })
                    .await?
                    .into_message();
                let ResponseProtocolOp::Bind {
                    server_sasl_creds,
                    status,
                } = ResponseProtocolOp::read_from(&mut body.as_slice())?
                else {
                    return Err(BindError::InvalidSchema);
                };
                let Some(return_token) = server_sasl_creds else {
                    return Ok((None, status));
                };
                ctx = match ctx.step(&return_token) {
                    StepOut::Pending(pending_client_context) => pending_client_context,
                    StepOut::Finished(f) => return Ok((Some(f), status)),
                }
            },
        }
    }

    async fn do_kerberos_negotiation_exchange(
        &self,
        ctx: ClientContext<Outbound, Signing, MaybeEncryption, MaybeDelegation>,
    ) -> Result<MaybeEncryptClientContext, BindError> {
        // Send empty token to prompt security layer negotiation
        let authentication = Authentication::sasl_kerberos(None);
        let body = self
            .send_message(RequestProtocolOp::Bind { authentication })
            .await?
            .into_message();
        let ResponseProtocolOp::Bind {
            server_sasl_creds: Some(server_sasl_creds),
            ..
        } = ResponseProtocolOp::read_from(&mut body.as_slice())?
        else {
            return Err(BindError::InvalidSchema);
        };
        let token_cleartext = ctx.unwrap(&server_sasl_creds).map_err(|_| BindError::GssAPI)?;
        let Some(token_cleartext): Option<[u8; 4]> = token_cleartext.as_array().copied() else {
            return Err(BindError::InvalidServerToken);
        };
        let Some(bind_offer) = BindSecurityOffer::highest_from_bitmask(token_cleartext[0]) else {
            return Err(BindError::InvalidServerToken);
        };

        let mut buffer = [0; 4];
        buffer[1..].copy_from_slice(&token_cleartext[1..4]);
        let _buffer_length = u32::from_be_bytes(buffer);
        let maybe_encrypt = ctx.check_encryption();
        let sign_only = match (bind_offer, &maybe_encrypt) {
            (BindSecurityOffer::None, _) => return Err(BindError::Insecure),
            (BindSecurityOffer::Signing, _) | (BindSecurityOffer::Encryption, Err(_)) => true,
            (BindSecurityOffer::Encryption, Ok(_)) => false,
        };
        buffer[0] = if sign_only { 0x2 } else { 0x4 };

        // Wrap the last token and send it
        let wrapped = match &maybe_encrypt {
            Ok(s) => s.sign(&buffer)?,
            Err(e) => e.sign(&buffer)?,
        };
        let kind = match maybe_encrypt {
            Ok(can_encrypt) => InnerContext::CanEncrypt(can_encrypt),
            Err(sign_only) => InnerContext::SignOnly(sign_only),
        };
        let encryption_layer = MaybeEncryptClientContext { kind, sign_only };
        let authentication = Authentication::sasl_kerberos(Some(&wrapped));
        let last_body = self
            .send_message(RequestProtocolOp::Bind { authentication })
            .await?
            .into_message();
        let ResponseProtocolOp::Bind {
            server_sasl_creds,
            status,
        } = ResponseProtocolOp::read_from(&mut last_body.as_slice())?
        else {
            return Err(BindError::InvalidSchema);
        };
        assert!(
            server_sasl_creds.is_none(),
            "Server should not have sent a token in the final step"
        );
        match status {
            BindStatus::Finished => Ok(encryption_layer),
            BindStatus::Pending => Err(BindError::InvalidServerToken),
        }
    }
}

async fn encrypt_stream(
    yoink_read_half: &mut mpsc::Sender<(oneshot::Sender<StreamReadHalf>, oneshot::Receiver<StreamReadHalf>)>,
    own_stream: &Mutex<Option<StreamWriteHalf>>,
    client_ctx: Arc<Mutex<MaybeEncryptClientContext>>,
) {
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
        stream = Stream::Kerberos(client_ctx, Default::default(), tcp)
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
pub enum BindError {
    Io(std::io::Error),
    ServerError { code: ResultCode, message: String },
    ChannelBind,
    SendOrReceive,
    GssAPI,
    Insecure,
    InvalidSchema,
    InvalidSecurityContext,
    InvalidServerToken,
}
impl From<WrapError> for BindError {
    fn from(_: WrapError) -> Self {
        Self::GssAPI
    }
}
impl From<SendMessageError> for BindError {
    fn from(value: SendMessageError) -> Self {
        match value {
            SendMessageError::Io(error) => BindError::Io(error),
            SendMessageError::ChannelClosed | SendMessageError::ReceiveMessage(_) => Self::SendOrReceive,
        }
    }
}
impl From<ReadProtocolOpError> for BindError {
    fn from(value: ReadProtocolOpError) -> Self {
        match value {
            ReadProtocolOpError::Io(io_err) => BindError::Io(io_err),
            ReadProtocolOpError::ProtocolError { code, message } => BindError::ServerError { code, message },
            ReadProtocolOpError::InvalidSchema => BindError::InvalidSchema,
        }
    }
}
