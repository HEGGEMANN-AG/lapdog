use std::{
    collections::HashMap,
    io::{ErrorKind, Write},
    num::NonZero,
    sync::{
        Arc,
        atomic::{AtomicI32, Ordering},
    },
};
use tokio::sync::{
    mpsc::{UnboundedReceiver as MReceiver, UnboundedSender as MSender},
    oneshot::{Receiver as OReceiver, Sender as OSender},
};

mod attribute;
mod auth;
mod bind;
mod compare;
mod integer;
mod length;
mod message;
mod parse;
mod read;
mod result;
pub mod search;
mod stream;
mod tag;

pub const LDAP_PORT: u16 = 389;
pub const LDAPS_PORT: u16 = 636;

pub(crate) use message::{RequestMessage, ResponseProtocolOp};
use tokio::{
    net::{TcpStream, ToSocketAddrs},
    sync::{
        Mutex, mpsc,
        oneshot::{Receiver, Sender},
    },
};

use crate::{
    message::RequestProtocolOp,
    read::ReadLdapError,
    stream::{Stream, StreamReadHalf, StreamWriteHalf},
};

const LDAP_VERSION: i32 = 3;

#[derive(Debug, Default)]
pub enum StreamConfig {
    #[default]
    Plain,
    #[cfg(feature = "native-tls")]
    NativeTls {
        connector: native_tls::TlsConnector,
        domain: String,
    },
}
impl StreamConfig {
    pub fn is_tls(&self) -> bool {
        match self {
            Self::Plain => false,
            #[cfg(feature = "native-tls")]
            Self::NativeTls { .. } => true,
        }
    }
}

enum InFlightRequestHandler {
    Single(OSender<Result<Vec<u8>, ReceiveMessageError>>),
    Multi(
        MSender<Result<Vec<u8>, ReceiveMessageError>>,
        Option<OReceiver<()>>,
    ),
}
impl InFlightRequestHandler {
    fn single() -> (Self, OReceiver<Result<Vec<u8>, ReceiveMessageError>>) {
        let (sx, rx) = tokio::sync::oneshot::channel();
        (Self::Single(sx), rx)
    }
    #[allow(clippy::type_complexity)]
    fn multi() -> (Self, MReceiver<Result<Vec<u8>, ReceiveMessageError>>, OSender<()>) {
        let (sx, rx) = tokio::sync::mpsc::unbounded_channel();
        let (shutdown_s, shutdown_r) = tokio::sync::oneshot::channel();
        (Self::Multi(sx, Some(shutdown_r)), rx, shutdown_s)
    }
}

type InFlightRequests = HashMap<NonZero<i32>, InFlightRequestHandler>;
pub struct LdapConnection {
    message_id: Arc<AtomicI32>,
    // only none while setting up channel bind
    tcp: Arc<Mutex<Option<StreamWriteHalf>>>,
    shutdown_sender: Option<Sender<()>>,
    yoink_read_half: mpsc::Sender<(Sender<StreamReadHalf>, Receiver<StreamReadHalf>)>,
    inflight_requests: Arc<Mutex<InFlightRequests>>,
}
impl LdapConnection {
    pub async fn new(addr: impl ToSocketAddrs, config: &StreamConfig) -> Self {
        let stream = TcpStream::connect(addr).await.unwrap();
        let (read, write) = match config {
            StreamConfig::Plain => Stream::Plain(stream),
            #[cfg(feature = "native-tls")]
            StreamConfig::NativeTls { connector, domain } => {
                let s = tokio_native_tls::TlsConnector::from(connector.clone())
                    .connect(domain, stream)
                    .await
                    .unwrap();
                Stream::NativeTls(s)
            }
        }
        .split();
        let message_id = Arc::new(AtomicI32::new(1));
        let (shutdown_sender, shutdown) = tokio::sync::oneshot::channel();
        let inflight_requests: Arc<Mutex<InFlightRequests>> = Arc::default();
        let (yoink_read_half, give_read_half) = tokio::sync::mpsc::channel(1);
        let tcp = Arc::new(Mutex::new(Some(write)));
        let new = LdapConnection {
            message_id,
            tcp,
            shutdown_sender: Some(shutdown_sender),
            yoink_read_half,
            inflight_requests: inflight_requests.clone(),
        };
        let fut = Self::drive(read, inflight_requests, give_read_half, shutdown);
        tokio::spawn(fut);
        new
    }
    async fn send_message(
        &self,
        protocol_op: RequestProtocolOp<'_>,
    ) -> Result<IncomingMessage, SendMessageError> {
        let message_id = self.message_id.fetch_add(1, Ordering::Relaxed);
        let id = NonZero::new(message_id).unwrap();
        let is_search = matches!(protocol_op, RequestProtocolOp::Search { .. });
        let bytes = RequestMessage {
            message_id: Some(id),
            protocol_op,
        }
        .to_bytes();
        if is_search {
            let (sx, rx, shutdown) = InFlightRequestHandler::multi();
            self.inflight_requests.lock().await.insert(id, sx);
            self.tcp
                .lock()
                .await
                .as_mut()
                .unwrap()
                .write_message(&bytes)
                .await
                .map_err(SendMessageError::Io)?;
            Ok(IncomingMessage::MessageReceiver(rx, shutdown))
        } else {
            let (sx, rx) = InFlightRequestHandler::single();
            self.inflight_requests.lock().await.insert(id, sx);
            self.tcp
                .lock()
                .await
                .as_mut()
                .unwrap()
                .write_message(&bytes)
                .await
                .map_err(SendMessageError::Io)?;
            match rx.await {
                Ok(Ok(values)) => Ok(IncomingMessage::Message(values)),
                Err(_) => Err(SendMessageError::ChannelClosed),
                Ok(Err(e)) => Err(SendMessageError::ReceiveMessage(e)),
            }
        }
    }
    async fn drive(
        read_half: StreamReadHalf,
        inflight_requests: Arc<Mutex<InFlightRequests>>,
        mut yoink_read_half: mpsc::Receiver<(Sender<StreamReadHalf>, Receiver<StreamReadHalf>)>,
        mut shutdown: Receiver<()>,
    ) {
        // only none while setting up channel bind
        let mut stream_opt = Some(read_half);
        loop {
            let (message_id, body) = tokio::select! {
                _ = &mut shutdown => return,
                b = stream_opt.as_mut().unwrap().get_next_message() => {
                    match b {
                        Ok(values) => values,
                        Err(ReadLdapError::Io(e)) if e.kind() == ErrorKind::ConnectionReset =>  {
                            break;
                        },
                        e => panic!("error checking message: {e:?}")
                    }
                },
                env = yoink_read_half.recv() => {
                    let Some((return_envelope, return_return_envelope)) = env else {
                        break;
                    };
                    let read_half = stream_opt.take().unwrap();
                    if return_envelope.send(read_half).is_err() {
                        panic!("read half was dropped before we could give it back to the main loop")
                    }
                    let Ok(returned_half) = return_return_envelope.await else {
                        break;
                    };
                    let _ = stream_opt.insert(returned_half);
                    continue;
                },
            };
            let Some(id) = NonZero::new(message_id) else {
                continue;
            };
            let mut inflight_lock = inflight_requests.lock().await;
            match inflight_lock.remove(&id) {
                None => continue,
                Some(InFlightRequestHandler::Single(sender)) => {
                    if let Err(e) = sender.send(Ok(body)) {
                        eprintln!("channel closed: {e:?}");
                    }
                }

                Some(InFlightRequestHandler::Multi(sender, shutdown)) => {
                    if sender.send(Ok(body)).is_err() {
                        continue;
                    }
                    if let Some(shutdown) = shutdown {
                        let ifr = inflight_requests.clone();
                        tokio::spawn(async move {
                            let _ = shutdown.await;
                            ifr.lock().await.remove(&id);
                        });
                    }
                    inflight_lock.insert(id, InFlightRequestHandler::Multi(sender, None));
                }
            }
        }
        inflight_requests.lock().await.drain().for_each(|(_, s)| match s {
            InFlightRequestHandler::Single(sender) => {
                let _ = sender.send(Err(ReceiveMessageError::ConnectionClosed));
            }
            InFlightRequestHandler::Multi(sender, _) => {
                let _ = sender.send(Err(ReceiveMessageError::ConnectionClosed));
            }
        });
    }
}
impl Drop for LdapConnection {
    fn drop(&mut self) {
        if let Some(sender) = self.shutdown_sender.take() {
            let _ = sender.send(());
        };
    }
}
enum IncomingMessage {
    Message(Vec<u8>),
    MessageReceiver(MReceiver<Result<Vec<u8>, ReceiveMessageError>>, OSender<()>),
}
impl IncomingMessage {
    fn into_message(self) -> Vec<u8> {
        let Self::Message(vec) = self else { panic!() };
        vec
    }
    fn into_receiver(self) -> (MReceiver<Result<Vec<u8>, ReceiveMessageError>>, OSender<()>) {
        let Self::MessageReceiver(recv, shutdown) = self else {
            panic!()
        };
        (recv, shutdown)
    }
}

#[derive(Debug)]
enum SendMessageError {
    Io(std::io::Error),
    ChannelClosed,
    ReceiveMessage(ReceiveMessageError),
}

#[derive(Debug)]
enum ReceiveMessageError {
    ConnectionClosed,
}

trait WriteExt: Write {
    fn write_single_byte(&mut self, b: u8) -> std::io::Result<()> {
        self.write_all(&[b])
    }
    fn write_ber_length(&mut self, length: usize) -> std::io::Result<()> {
        crate::length::write_length(self, length)?;
        Ok(())
    }
    fn write_ber_integer(&mut self, i: i32) -> std::io::Result<()> {
        crate::integer::write_integer(i, self)?;
        Ok(())
    }
}
impl<W: Write> WriteExt for W {}

#[cfg(test)]
pub mod test {
    use kenobi::mech::Mechanism;

    use crate::{
        LdapConnection,
        search::{DerefPolicy, Filter, Scope, SearchResult},
    };

    #[cfg(feature = "kerberos")]
    async fn test_no_tls(mech: Mechanism) {
        use kenobi::cred::Credentials;

        use crate::{LDAP_PORT, LdapConnection, StreamConfig};
        let server = std::env::var("LAPDOG_SERVER").unwrap();
        let target_spn = std::env::var("LAPDOG_TARGET_SPN").ok();
        let own_spn = std::env::var("LAPDOG_OWN_SPN").ok();
        let cred = Credentials::outbound(own_spn.as_deref(), mech).unwrap();
        let mut connection = LdapConnection::new(&(server, LDAP_PORT), &StreamConfig::default()).await;
        connection
            .bind_sasl_kenobi(cred.clone(), target_spn.as_deref())
            .await
            .unwrap();
        test_search(&mut connection).await
    }
    #[tokio::test(flavor = "multi_thread")]
    #[cfg(feature = "kerberos")]
    async fn bind_kerberos() {
        test_no_tls(Mechanism::KerberosV5).await
    }
    #[tokio::test(flavor = "multi_thread")]
    #[cfg(feature = "kerberos")]
    async fn bind_spnego() {
        test_no_tls(Mechanism::Spnego).await
    }

    #[cfg(all(feature = "kerberos", feature = "native-tls"))]
    async fn test_tls(mech: Mechanism) {
        use kenobi::cred::Credentials;
        use native_tls::TlsConnector;

        use crate::{LDAPS_PORT, LdapConnection, StreamConfig};
        let server = std::env::var("LAPDOG_SERVER").unwrap();
        let target_spn = std::env::var("LAPDOG_TARGET_SPN").ok();
        let own_spn = std::env::var("LAPDOG_OWN_SPN").ok();
        let root = std::env::var("LAPDOG_ROOT_CERT").ok();
        let domain = std::env::var("LAPDOG_DOMAIN").unwrap();
        let cred = Credentials::outbound(own_spn.as_deref(), mech).unwrap();
        let mut connector = TlsConnector::builder();
        if let Some(root) = root {
            let file = std::fs::read(root).unwrap();
            let cert = native_tls::Certificate::from_pem(&file).unwrap();
            connector.add_root_certificate(cert);
        }
        let connector = connector.build().unwrap();
        let mut connection = LdapConnection::new(
            &(server, LDAPS_PORT),
            &StreamConfig::NativeTls { connector, domain },
        )
        .await;
        connection
            .bind_sasl_kenobi(cred, target_spn.as_deref())
            .await
            .unwrap();
        test_search(&mut connection).await
    }

    #[tokio::test(flavor = "multi_thread")]
    #[cfg(all(feature = "kerberos", feature = "native-tls"))]
    async fn tls_bind_kerberos() {
        test_tls(Mechanism::KerberosV5).await
    }

    #[tokio::test(flavor = "multi_thread")]
    #[cfg(all(feature = "kerberos", feature = "native-tls"))]
    async fn tls_bind_spnego() {
        test_tls(Mechanism::Spnego).await
    }

    async fn test_search(ldap: &mut LdapConnection) {
        let filter = Filter::Present("userPrincipalName");
        let search_base = std::env::var("LAPDOG_TEST_SEARCH_BASE").unwrap();
        let mut search = ldap
            .search(
                &search_base,
                Scope::WholeSubtree,
                DerefPolicy::InSearching,
                filter,
                vec!["userPrincipalName"],
            )
            .await;
        let mut count = 0;
        loop {
            use std::time::Duration;

            match tokio::time::timeout(Duration::from_secs(4), search.next()).await {
                Ok(Some(Ok(SearchResult::Entry(raw_entry)))) => {
                    dbg!(raw_entry);
                    count += 1
                }
                Ok(Some(Err(e))) => println!("Encountered search error: {e:?}"),
                Ok(Some(Ok(SearchResult::Reference))) => {}
                Ok(Some(Ok(SearchResult::Done { .. }))) | Ok(None) | Err(_) => break,
            };
        }
        println!("Server sent {count} entries")
    }
}
