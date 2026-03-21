#[cfg(feature = "kerberos")]
use std::collections::VecDeque;
use std::{io::Read, pin::Pin, sync::Arc};

#[cfg(feature = "native-tls")]
use tokio::io::{ReadHalf, WriteHalf};
#[cfg(feature = "kerberos")]
use tokio::sync::Mutex;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{
        TcpStream,
        tcp::{OwnedReadHalf, OwnedWriteHalf},
    },
};

#[cfg(feature = "kerberos")]
use crate::bind::kerberos::MaybeEncryptClientContext;
use crate::{
    parse::ParseLdap,
    read::{AsyncReadLdap, ReadExt, ReadLdap},
    tag::{UNIVERSAL_INTEGER, UNIVERSAL_SEQUENCE},
};

pub enum StreamWriteHalf {
    Plain(OwnedWriteHalf),
    #[cfg(feature = "native-tls")]
    NativeTls(WriteHalf<tokio_native_tls::TlsStream<TcpStream>>),
    #[cfg(feature = "kerberos")]
    Kerberos(Arc<Mutex<MaybeEncryptClientContext>>, OwnedWriteHalf),
}
impl StreamWriteHalf {
    pub async fn write_message(&mut self, m: &[u8]) -> Result<(), std::io::Error> {
        match self {
            StreamWriteHalf::Plain(owned_write_half) => owned_write_half.write_all(m).await,
            #[cfg(feature = "native-tls")]
            StreamWriteHalf::NativeTls(write_half) => write_half.write_all(m).await,
            #[cfg(feature = "kerberos")]
            StreamWriteHalf::Kerberos(client_context, write_half) => {
                let mut write_half = Pin::new(write_half);
                let encrypt = Pin::new(client_context.lock().await).wrap_best(m);
                let buf = [(encrypt.len() as i32).to_be_bytes().as_slice(), &encrypt].concat();
                write_half.write_all(&buf).await?;
                write_half.flush().await
            }
        }
    }
}

pub enum StreamReadHalf {
    Plain(OwnedReadHalf),
    #[cfg(feature = "native-tls")]
    NativeTls(ReadHalf<tokio_native_tls::TlsStream<TcpStream>>),
    #[cfg(feature = "kerberos")]
    Kerberos(Arc<Mutex<MaybeEncryptClientContext>>, VecDeque<u8>, OwnedReadHalf),
}
impl StreamReadHalf {
    pub async fn get_next_message(&mut self) -> Result<(i32, Vec<u8>), std::io::Error> {
        match self {
            StreamReadHalf::Plain(owned_read_half) => Ok(read_message_head_async(owned_read_half).await),
            #[cfg(feature = "native-tls")]
            StreamReadHalf::NativeTls(read_half) => Ok(read_message_head_async(read_half).await),
            #[cfg(feature = "kerberos")]
            StreamReadHalf::Kerberos(ctx, buffer, owned_read_half) => {
                if buffer.is_empty() {
                    use std::io::Write;

                    let size = owned_read_half.read_u32().await?;
                    let mut buf = vec![0u8; size as usize];
                    owned_read_half.read_exact(&mut buf).await?;
                    let c = ctx.lock().await.unwrap(&buf).unwrap().to_vec();
                    buffer.write_all(&c).unwrap();
                }
                Ok(read_message_head_sync(buffer))
            }
        }
    }
}

async fn read_message_head_async<R: AsyncReadExt + Unpin>(r: &mut R) -> (i32, Vec<u8>) {
    let seq_tag = r.read_u8().await.unwrap();
    if seq_tag != UNIVERSAL_SEQUENCE {
        panic!("Not a sequence");
    }
    let (Some(len), _) = r.read_length().await.unwrap() else {
        panic!()
    };
    let mut buffer = vec![0; len];
    r.read_exact(&mut buffer).await.unwrap();
    let mut buf_read = buffer.as_slice();
    let (tag, message_id) = buf_read.read_as_tag_integer().unwrap();
    if tag != UNIVERSAL_INTEGER {
        panic!("message id is not an int");
    }
    (message_id, buf_read.to_vec())
}

fn read_message_head_sync<R: Read>(r: &mut R) -> (i32, Vec<u8>) {
    let seq_tag = r.read_single_byte().unwrap();
    if seq_tag != UNIVERSAL_SEQUENCE {
        panic!("Not a sequence");
    }
    let (Some(len), _) = r.read_length().unwrap() else {
        panic!()
    };
    let mut buffer = vec![0; len];
    r.read_exact(&mut buffer).unwrap();
    let mut buf_read = buffer.as_slice();
    let (tag, message_id) = buf_read.read_as_tag_integer().unwrap();
    if tag != UNIVERSAL_INTEGER {
        panic!("message id is not an int");
    }
    (message_id, buf_read.to_vec())
}

#[allow(clippy::large_enum_variant)]
pub enum Stream {
    Plain(TcpStream),
    #[cfg(feature = "native-tls")]
    NativeTls(tokio_native_tls::TlsStream<TcpStream>),
    #[cfg(feature = "kerberos")]
    Kerberos(Arc<Mutex<MaybeEncryptClientContext>>, VecDeque<u8>, TcpStream),
}
impl Stream {
    pub fn split(self) -> (StreamReadHalf, StreamWriteHalf) {
        match self {
            Self::Plain(p) => {
                let (r, w) = p.into_split();
                (StreamReadHalf::Plain(r), StreamWriteHalf::Plain(w))
            }
            #[cfg(feature = "native-tls")]
            Self::NativeTls(n) => {
                let (r, w) = tokio::io::split(n);
                (StreamReadHalf::NativeTls(r), StreamWriteHalf::NativeTls(w))
            }
            #[cfg(feature = "kerberos")]
            Self::Kerberos(client, buf, tcp) => {
                let (r, w) = tcp.into_split();
                (
                    StreamReadHalf::Kerberos(client.clone(), buf, r),
                    StreamWriteHalf::Kerberos(client, w),
                )
            }
        }
    }
    #[cfg(feature = "kerberos")]
    pub fn unsplit(read: StreamReadHalf, write: StreamWriteHalf) -> Self {
        match (read, write) {
            (StreamReadHalf::Plain(owned_read_half), StreamWriteHalf::Plain(owned_write_half)) => {
                Stream::Plain(owned_read_half.reunite(owned_write_half).unwrap())
            }
            #[cfg(feature = "native-tls")]
            (StreamReadHalf::NativeTls(read_half), StreamWriteHalf::NativeTls(write_half)) => {
                Stream::NativeTls(read_half.unsplit(write_half))
            }
            #[cfg(feature = "kerberos")]
            (
                StreamReadHalf::Kerberos(client, buf, owned_read_half),
                StreamWriteHalf::Kerberos(_, owned_write_half),
            ) => Stream::Kerberos(client, buf, owned_read_half.reunite(owned_write_half).unwrap()),
            #[cfg(any(feature = "native-tls", feature = "kerberos"))]
            _ => unreachable!(),
        }
    }
}

#[cfg(feature = "kerberos")]
pub mod channel_bindings {
    use std::fmt::Display;

    use kenobi::channel_bindings::Channel;

    use crate::stream::Stream;

    impl Channel for Stream {
        type Error = ChannelBindingError;
        fn channel_bindings(&self) -> Result<Option<Vec<u8>>, Self::Error> {
            match self {
                Stream::Plain(_) => Ok(None),
                #[cfg(feature = "native-tls")]
                Stream::NativeTls(tls_stream) => tls_stream
                    .get_ref()
                    .channel_bindings()
                    .map_err(ChannelBindingError::Native),
                #[cfg(feature = "kerberos")]
                Stream::Kerberos(_, _, _) => Ok(None),
            }
        }
    }

    #[derive(Debug)]
    pub enum ChannelBindingError {
        #[cfg(feature = "native-tls")]
        Native(native_tls::Error),
    }
    impl std::error::Error for ChannelBindingError {
        fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
            match self {
                #[cfg(feature = "native-tls")]
                Self::Native(e) => Some(e),
                #[cfg(not(feature = "native-tls"))]
                _ => todo!(),
            }
        }
    }
    impl Display for ChannelBindingError {
        fn fmt(&self, _f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            match self {
                #[cfg(feature = "native-tls")]
                Self::Native(n) => n.fmt(_f),
                #[cfg(not(feature = "native-tls"))]
                _ => todo!(),
            }
        }
    }
}
