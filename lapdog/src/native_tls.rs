use std::{
    fmt::Debug,
    io::{Read, Write},
    net::{TcpStream, ToSocketAddrs},
};

pub use native_tls::TlsConnector;
use native_tls::{HandshakeError, TlsStream};
use rasn_ldap::{ExtendedRequest, ExtendedResponse, LdapString, ProtocolOp, ResultCode};

use crate::{LdapConnection, MessageError, bind::native_tls::BoundNativeTls};

#[derive(Debug)]
pub enum ConnectError {
    Io(std::io::Error),
    Tls(Box<native_tls::HandshakeError<TcpStream>>),
}
impl std::error::Error for ConnectError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Io(io) => Some(io),
            Self::Tls(tls) => Some(tls),
        }
    }
}
impl std::fmt::Display for ConnectError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Io(io) => write!(f, "Failed to open connection: {io}"),
            Self::Tls(tls) => write!(f, "Failed to establish secure channel: {tls}"),
        }
    }
}

impl LdapConnection<TlsStream<TcpStream>, BoundNativeTls> {
    pub fn connect_native_tls(
        addr: impl ToSocketAddrs,
        domain: &str,
        tls_connector: native_tls::TlsConnector,
    ) -> Result<LdapConnection<TlsStream<TcpStream>>, ConnectError> {
        let tcp = TcpStream::connect(addr).map_err(ConnectError::Io)?;
        let tls = tls_connector
            .connect(domain, tcp)
            .map_err(|e| ConnectError::Tls(Box::new(e)))?;
        Ok(LdapConnection::new_unbound(tls))
    }
}
impl<T, BindState> LdapConnection<T, BindState>
where
    T: Read + Write + std::fmt::Debug,
{
    const STARTTLS_MESSAGE_NAME: &[u8] = b"1.3.6.1.4.1.1466.20037";
    pub fn start_native_tls(
        mut self,
        domain: &str,
        tls_connector: native_tls::TlsConnector,
    ) -> Result<LdapConnection<TlsStream<T>, BindState>, UpgradeError<T, BindState>> {
        let op = ProtocolOp::ExtendedReq(ExtendedRequest {
            request_name: Self::STARTTLS_MESSAGE_NAME.into(),
            request_value: None,
        });
        match self.send_single_message(op, None) {
            Err(MessageError::Message(_)) => Err(UpgradeError::InvalidMessage),
            Err(MessageError::Io(io)) => Err(UpgradeError::Io(io)),
            Ok(ProtocolOp::ExtendedResp(ExtendedResponse {
                response_name: Some(oc),
                result_code,
                diagnostic_message: LdapString(message),
                ..
            })) if oc == Self::STARTTLS_MESSAGE_NAME => {
                if result_code == ResultCode::Success {
                    let stream = tls_connector
                        .connect(domain, self.stream)
                        .map_err(|hs| UpgradeError::Handshake(Box::new(hs)))?;
                    Ok(LdapConnection {
                        state: self.state,
                        stream,
                        next_message_id: self.next_message_id,
                    })
                } else {
                    Err(UpgradeError::Refused {
                        connection: self,
                        message: message.into_boxed_str(),
                        code: result_code,
                    })
                }
            }
            _ => Err(UpgradeError::InvalidMessage),
        }
    }
}

pub enum UpgradeError<T, BindState>
where
    T: Read + Write + Debug,
{
    Io(std::io::Error),
    Handshake(Box<HandshakeError<T>>),
    InvalidMessage,
    Refused {
        connection: LdapConnection<T, BindState>,
        code: ResultCode,
        message: Box<str>,
    },
}
impl<T: Read + Write + Debug, BindState> Debug for UpgradeError<T, BindState> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidMessage => write!(f, "{:?}", "InvalidMessage"),
            Self::Io(io) => {
                let mut map = f.debug_map();
                map.entry(&"Io", io);
                map.finish()
            }
            Self::Handshake(hs) => {
                let mut tup = f.debug_tuple("Handshake");
                tup.field(hs);
                tup.finish()
            }
            Self::Refused { code, message, .. } => {
                let mut stru = f.debug_struct("Refused");
                stru.field("code", code);
                stru.field("message", message);
                stru.finish()
            }
        }
    }
}
impl<T: Read + Write + Debug + 'static, BindState> std::error::Error for UpgradeError<T, BindState> {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Handshake(hs) => Some(hs),
            Self::Io(io) => Some(io),
            _ => None,
        }
    }
}
impl<T: Read + Write + Debug + 'static, BindState> std::fmt::Display for UpgradeError<T, BindState> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidMessage => write!(f, "Server sent an invalid message format"),
            Self::Handshake(hs) => write!(f, "Tls handshake failed: {hs}"),
            Self::Io(io) => write!(f, "error writing message to stream: {io}"),
            Self::Refused { code, message, .. } => {
                write!(
                    f,
                    "server refused upgrade with code {code:?} and message \"{message}\"."
                )
            }
        }
    }
}
