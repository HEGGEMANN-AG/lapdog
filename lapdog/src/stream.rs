use std::{
    pin::Pin,
    task::{Context, Poll},
};

#[cfg(feature = "native-tls")]
use tokio::io::{ReadHalf, WriteHalf};
use tokio::{
    io::{AsyncRead, AsyncWrite},
    net::{
        TcpStream,
        tcp::{OwnedReadHalf, OwnedWriteHalf},
    },
};

pub trait StreamPart {
    fn is_tls(&self) -> bool;
}

#[derive(Debug)]
pub enum StreamWriteHalf {
    Plain(OwnedWriteHalf),
    #[cfg(feature = "native-tls")]
    NativeTls(WriteHalf<tokio_native_tls::TlsStream<TcpStream>>),
}
impl StreamPart for StreamWriteHalf {
    fn is_tls(&self) -> bool {
        match self {
            Self::Plain(_) => false,
            #[cfg(feature = "native-tls")]
            Self::NativeTls(_) => true,
        }
    }
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
        }
    }
    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        let this = &mut *self;
        match this {
            StreamWriteHalf::Plain(owned_write_half) => Pin::new(owned_write_half).poll_flush(cx),
            #[cfg(feature = "native-tls")]
            StreamWriteHalf::NativeTls(write_half) => Pin::new(write_half).poll_flush(cx),
        }
    }
    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        let this = &mut *self;
        match this {
            StreamWriteHalf::Plain(owned_write_half) => {
                Pin::new(owned_write_half).poll_shutdown(cx)
            }
            #[cfg(feature = "native-tls")]
            StreamWriteHalf::NativeTls(write_half) => Pin::new(write_half).poll_shutdown(cx),
        }
    }
}
#[derive(Debug)]
pub enum StreamReadHalf {
    Plain(OwnedReadHalf),
    #[cfg(feature = "native-tls")]
    NativeTls(ReadHalf<tokio_native_tls::TlsStream<TcpStream>>),
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
        }
    }
}
impl StreamPart for StreamReadHalf {
    fn is_tls(&self) -> bool {
        match self {
            Self::Plain(_) => false,
            #[cfg(feature = "native-tls")]
            Self::NativeTls(_) => true,
        }
    }
}
#[derive(Debug)]
pub enum Stream {
    Plain(TcpStream),
    #[cfg(feature = "native-tls")]
    NativeTls(tokio_native_tls::TlsStream<TcpStream>),
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
            #[cfg(feature = "native-tls")]
            _ => unreachable!(),
        }
    }
}
impl StreamPart for Stream {
    fn is_tls(&self) -> bool {
        match self {
            Self::Plain(_) => false,
            #[cfg(feature = "native-tls")]
            Self::NativeTls(_) => true,
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
