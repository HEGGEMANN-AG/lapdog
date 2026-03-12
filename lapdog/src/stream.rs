use std::{
    ops::Deref,
    pin::Pin,
    sync::Arc,
    task::{Context, Poll},
};

#[cfg(feature = "kerberos")]
use kenobi::{
    client::ClientContext,
    cred::Outbound,
    typestate::{Encryption, MaybeDelegation, Signing},
};
#[cfg(feature = "native-tls")]
use tokio::io::{ReadHalf, WriteHalf};
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite},
    net::{
        TcpStream,
        tcp::{OwnedReadHalf, OwnedWriteHalf},
    },
};

use crate::read::{AsyncReadLdap, ReadLdap, ReadLdapError};

pub enum StreamWriteHalf {
    Plain(OwnedWriteHalf),
    #[cfg(feature = "native-tls")]
    NativeTls(WriteHalf<tokio_native_tls::TlsStream<TcpStream>>),
    #[cfg(feature = "kerberos")]
    Kerberos(
        Arc<ClientContext<Outbound, Signing, Encryption, MaybeDelegation>>,
        OwnedWriteHalf,
    ),
}

impl AsyncWrite for StreamWriteHalf {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        let this = &mut *self;
        match this {
            Self::Plain(p) => Pin::new(p).poll_write(cx, buf),
            #[cfg(feature = "native-tls")]
            Self::NativeTls(n) => Pin::new(n).poll_write(cx, buf),
            #[cfg(feature = "kerberos")]
            Self::Kerberos(client_context, write_half) => {
                let mut write_half = Pin::new(write_half);
                let client_context = Pin::new(client_context);
                let encrypt = client_context.encrypt(buf).unwrap();
                let mut buf = vec![0; 4 + encrypt.len()];
                buf[..4].copy_from_slice(&(encrypt.len() as u32).to_be_bytes());
                buf[4..].copy_from_slice(&encrypt);
                match write_half.as_mut().poll_write(cx, encrypt.as_ref()) {
                    Poll::Ready(Ok(n)) => Poll::Ready(Ok(n)),
                    Poll::Ready(Err(e)) => Poll::Ready(Err(e)),
                    Poll::Pending => Poll::Pending,
                }
            }
        }
    }
    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        let this = &mut *self;
        match this {
            StreamWriteHalf::Plain(owned_write_half) => Pin::new(owned_write_half).poll_flush(cx),
            #[cfg(feature = "native-tls")]
            StreamWriteHalf::NativeTls(write_half) => Pin::new(write_half).poll_flush(cx),
            #[cfg(feature = "kerberos")]
            StreamWriteHalf::Kerberos(_, write_half) => Pin::new(write_half).poll_flush(cx),
        }
    }
    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        let this = &mut *self;
        match this {
            StreamWriteHalf::Plain(owned_write_half) => Pin::new(owned_write_half).poll_shutdown(cx),
            #[cfg(feature = "native-tls")]
            StreamWriteHalf::NativeTls(write_half) => Pin::new(write_half).poll_shutdown(cx),
            #[cfg(feature = "kerberos")]
            StreamWriteHalf::Kerberos(_, write_half) => Pin::new(write_half).poll_shutdown(cx),
        }
    }
}
pub enum StreamReadHalf {
    Plain(OwnedReadHalf),
    #[cfg(feature = "native-tls")]
    NativeTls(ReadHalf<tokio_native_tls::TlsStream<TcpStream>>),
    #[cfg(feature = "kerberos")]
    Kerberos(
        Arc<ClientContext<Outbound, Signing, Encryption, MaybeDelegation>>,
        OwnedReadHalf,
    ),
}
impl StreamReadHalf {
    pub async fn get_next_message(&mut self) -> Result<(i32, Vec<u8>), ReadLdapError> {
        match self {
            StreamReadHalf::Plain(owned_read_half) => owned_read_half.read_message_head().await,
            #[cfg(feature = "native-tls")]
            StreamReadHalf::NativeTls(read_half) => read_half.read_message_head().await,
            #[cfg(feature = "kerberos")]
            StreamReadHalf::Kerberos(ctx, owned_read_half) => {
                let size = owned_read_half.read_u32().await.map_err(ReadLdapError::Io)?;
                let mut buf = vec![0u8; dbg!(size) as usize];
                owned_read_half
                    .read_exact(&mut buf)
                    .await
                    .map_err(ReadLdapError::Io)?;
                let c = ctx.unwrap(&buf).unwrap();
                let mut cleartext_slice = c.deref();
                ReadLdap::read_message_head(&mut cleartext_slice)
            }
        }
    }
}
impl AsyncRead for StreamReadHalf {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        let this = &mut *self;
        match this {
            Self::Plain(p) => Pin::new(p).poll_read(cx, buf),
            #[cfg(feature = "native-tls")]
            Self::NativeTls(n) => Pin::new(n).poll_read(cx, buf),
            #[cfg(feature = "kerberos")]
            Self::Kerberos(_, read_half) => {
                let mut read_half = Pin::new(read_half);
                read_half.as_mut().poll_read(cx, buf)
            }
        }
    }
}
#[allow(clippy::large_enum_variant)]
pub enum Stream {
    Plain(TcpStream),
    #[cfg(feature = "native-tls")]
    NativeTls(tokio_native_tls::TlsStream<TcpStream>),
    #[cfg(feature = "kerberos")]
    Kerberos(
        Arc<ClientContext<Outbound, Signing, Encryption, MaybeDelegation>>,
        TcpStream,
    ),
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
            Self::Kerberos(client, tcp) => {
                let (r, w) = tcp.into_split();
                (
                    StreamReadHalf::Kerberos(client.clone(), r),
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
                StreamReadHalf::Kerberos(client, owned_read_half),
                StreamWriteHalf::Kerberos(_, owned_write_half),
            ) => Stream::Kerberos(client, owned_read_half.reunite(owned_write_half).unwrap()),
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
                Stream::Kerberos(_, _) => Ok(None),
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
