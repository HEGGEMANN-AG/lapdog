use std::{
    fmt::Display,
    net::{TcpStream, ToSocketAddrs},
    sync::Arc,
};

use crate::LdapConnection;
use rustls::{
    ClientConfig, ClientConnection, StreamOwned,
    pki_types::{InvalidDnsNameError, ServerName},
};

pub struct BoundRustls {
    _priv: (),
}
impl BoundRustls {
    pub(crate) fn new() -> Self {
        Self { _priv: () }
    }
}
impl LdapConnection<StreamOwned<ClientConnection, TcpStream>> {
    pub fn connect_rustls(
        addr: impl ToSocketAddrs,
        server: &str,
        config: impl Into<Arc<ClientConfig>>,
    ) -> Result<LdapConnection<StreamOwned<ClientConnection, TcpStream>, BoundRustls>, ConnectError> {
        let tcp = TcpStream::connect(addr).map_err(ConnectError::Io)?;
        let server = server.to_owned();
        let con = ClientConnection::new(
            config.into(),
            ServerName::try_from(server).map_err(ConnectError::InvalidServerName)?,
        )
        .map_err(ConnectError::Tls)?;
        let stream = StreamOwned::new(con, tcp);
        Ok(LdapConnection {
            stream,
            next_message_id: 1,
            state: BoundRustls::new(),
        })
    }
}

#[derive(Debug)]
pub enum ConnectError {
    Io(std::io::Error),
    InvalidServerName(InvalidDnsNameError),
    Tls(rustls::Error),
}
impl std::error::Error for ConnectError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Io(io) => Some(io),
            Self::InvalidServerName(_) => None,
            Self::Tls(tls) => Some(tls),
        }
    }
}
impl Display for ConnectError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Io(io) => write!(f, "error connecting to socket: {io}"),
            Self::InvalidServerName(i) => write!(f, "Invalid server name: {i}"),
            Self::Tls(tls) => write!(f, "Rustls error: {tls}"),
        }
    }
}
