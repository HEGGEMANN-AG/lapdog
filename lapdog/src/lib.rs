use std::{
    collections::HashMap,
    io::{Read, Write},
    num::NonZero,
    sync::{
        Arc,
        atomic::{AtomicI32, Ordering},
    },
};

mod auth;
mod bind;
mod integer;
mod length;
mod message;
mod result;
mod stream;
mod tag;

pub const LDAP_PORT: u16 = 389;
pub const LDAPS_PORT: u16 = 636;

pub use message::{Message, RequestMessage, ResponseProtocolOp};
use tokio::{
    io::AsyncReadExt,
    net::{TcpStream, ToSocketAddrs},
    sync::{
        Mutex,
        oneshot::{Receiver, Sender},
    },
};

use crate::{
    integer::read_integer_body,
    message::RequestProtocolOp,
    stream::{Stream, StreamReadHalf, StreamWriteHalf},
    tag::{PrimitiveOrConstructed, TagClass, is_tag_triple},
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

type InFlightRequests = HashMap<NonZero<i32>, Sender<(i32, Vec<u8>)>>;
#[derive(Debug)]
pub struct LdapConnection {
    message_id: Arc<AtomicI32>,
    // only none while setting up channel bind
    tcp: Arc<Mutex<Option<StreamWriteHalf>>>,
    shutdown_sender: Option<Sender<()>>,
    yoink_read_half: tokio::sync::mpsc::Sender<(Sender<StreamReadHalf>, Receiver<StreamReadHalf>)>,
    inflight_requests: Arc<Mutex<InFlightRequests>>,
}
impl LdapConnection {
    pub async fn new(addr: impl ToSocketAddrs, config: &StreamConfig) -> Arc<Self> {
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
        Arc::new(new)
    }
    async fn send_message(&self, protocol_op: RequestProtocolOp<'_>) -> (i32, Vec<u8>) {
        let message_id = self.message_id.fetch_add(1, Ordering::Relaxed);
        let id = NonZero::new(message_id).unwrap();
        let (sx, rx) = tokio::sync::oneshot::channel();
        self.inflight_requests.lock().await.insert(id, sx);
        let mut tcp = self.tcp.lock().await;
        let msg = RequestMessage {
            message_id: Some(id),
            protocol_op,
        };
        msg.write_to_async(tcp.as_mut().unwrap()).await.unwrap();
        rx.await.unwrap()
    }
    async fn drive(
        read_half: StreamReadHalf,
        inflight_requests: Arc<Mutex<InFlightRequests>>,
        mut yoink_read_half: tokio::sync::mpsc::Receiver<(
            Sender<StreamReadHalf>,
            Receiver<StreamReadHalf>,
        )>,
        mut shutdown: Receiver<()>,
    ) {
        // only none while setting up channel bind
        let mut stream_opt = Some(read_half);
        loop {
            let (message_id, body) = tokio::select! {
                _ = &mut shutdown => return,
                b = stream_opt.as_mut().unwrap().read_message_head() => b.unwrap(),
                env = yoink_read_half.recv() => {
                    let Some((return_envelope, return_return_envelope)) = env else {
                        return;
                    };
                    let read_half = stream_opt.take().unwrap();
                    return_envelope.send(read_half).unwrap();
                    let Ok(returned_half) = return_return_envelope.await else {
                        return;
                    };
                    let _ = stream_opt.insert(returned_half);
                    continue;
                },
            };
            let Some(id) = NonZero::new(message_id) else {
                continue;
            };
            let Some(sender) = inflight_requests.lock().await.remove(&id) else {
                continue;
            };
            if let Err(e) = sender.send((message_id, body)) {
                eprintln!("channel closed: {e:?}");
            }
        }
    }
}
impl Drop for LdapConnection {
    fn drop(&mut self) {
        if let Some(sender) = self.shutdown_sender.take() {
            let _ = sender.send(());
        };
    }
}

trait ReadExt: Read {
    fn read_single_byte(&mut self) -> std::io::Result<u8> {
        let mut b = 0;
        self.read_exact(std::slice::from_mut(&mut b))?;
        Ok(b)
    }
}
impl<R: Read> ReadExt for R {}
trait AsyncReadLdap: AsyncReadExt + Unpin {
    async fn read_message_head(&mut self) -> std::io::Result<(i32, Vec<u8>)> {
        let seq_tag = self.read_u8().await?;
        if !is_tag_triple(
            seq_tag,
            tag::TagClass::Universal,
            PrimitiveOrConstructed::Constructed,
            0b00010000,
        ) {
            panic!("message is a sequence");
        }
        let (seq_length, _) = self.read_length().await.unwrap();
        let seq_length = seq_length.unwrap();
        let (int_tag, message_id, int_len) = self.read_integer_unverified().await.unwrap();
        if !is_tag_triple(
            int_tag,
            TagClass::Universal,
            PrimitiveOrConstructed::Primitive,
            0x02,
        ) {
            panic!("not an integer");
        }

        let mut buffer = vec![0; seq_length - int_len];
        self.read_exact(&mut buffer).await.unwrap();
        Ok((message_id, buffer))
    }
    /// Returns logical length of object, and then number of read bytes
    async fn read_length(&mut self) -> std::io::Result<(Option<usize>, usize)> {
        let first = self.read_u8().await?;
        match first {
            val @ 0..0x80 => Ok((Some(val.into()), 1)),
            0x80 => Ok((None, 1)),
            val @ 0x80.. => {
                let length_bytes = (val & 0x7F) as usize;
                if length_bytes > size_of::<usize>() {
                    unimplemented!()
                }
                let mut length = [0; size_of::<usize>()];
                self.read_exact(&mut length[size_of::<usize>() - length_bytes..])
                    .await?;
                Ok((Some(usize::from_be_bytes(length)), 1 + length_bytes))
            }
        }
    }
    async fn read_integer_unverified(&mut self) -> std::io::Result<(u8, i32, usize)> {
        let int_tag = self.read_u8().await?;
        let (Some(int_len), len_len) = self.read_length().await? else {
            panic!("Length undefined");
        };
        let mut intbuf = vec![0; int_len];
        self.read_exact(&mut intbuf).await?;
        let i = read_integer_body(&intbuf).unwrap();
        Ok((int_tag, i, 1 + len_len + int_len))
    }
}
impl<A: AsyncReadExt + Unpin> AsyncReadLdap for A {}

trait WriteExt: Write {
    fn write_single_byte(&mut self, b: u8) -> std::io::Result<()> {
        self.write_all(&[b])
    }
    fn write_ber_integer(&mut self, i: i32) -> std::io::Result<()> {
        crate::integer::write_integer(i, self)?;
        Ok(())
    }
}
impl<W: Write> WriteExt for W {}

#[cfg(test)]
mod test {
    #[tokio::test(flavor = "multi_thread")]
    #[cfg(feature = "kerberos")]
    async fn bind_kerberos() {
        use std::sync::Arc;

        use kenobi::cred::Credentials;

        use crate::{LDAP_PORT, LdapConnection, StreamConfig};
        let server = std::env::var("LAPDOG_SERVER").unwrap();
        let target_spn = std::env::var("LAPDOG_TARGET_SPN").ok();
        let own_spn = std::env::var("LAPDOG_OWN_SPN").ok();
        let cred = Credentials::outbound(own_spn.as_deref()).unwrap();
        let mut connection =
            LdapConnection::new(&(server, LDAP_PORT), &StreamConfig::default()).await;
        Arc::get_mut(&mut connection)
            .unwrap()
            .bind_kerberos(&cred, target_spn.as_deref())
            .await
            .unwrap();
        todo!()
    }

    #[tokio::test(flavor = "multi_thread")]
    #[cfg(all(feature = "kerberos", feature = "native-tls"))]
    async fn bind_kerberos_tls() {
        use std::sync::Arc;

        use kenobi::cred::Credentials;
        use native_tls::TlsConnector;

        use crate::{LDAPS_PORT, LdapConnection, StreamConfig};
        let server = std::env::var("LAPDOG_SERVER").unwrap();
        let target_spn = std::env::var("LAPDOG_TARGET_SPN").ok();
        let own_spn = std::env::var("LAPDOG_OWN_SPN").ok();
        let root = std::env::var("LAPDOG_ROOT_CERT").ok();
        let domain = std::env::var("LAPDOG_DOMAIN").unwrap();
        let cred = Credentials::outbound(own_spn.as_deref()).unwrap();
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
        Arc::get_mut(&mut connection)
            .unwrap()
            .bind_kerberos(&cred, target_spn.as_deref())
            .await
            .unwrap();
        todo!()
    }
}
