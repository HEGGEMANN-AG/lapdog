use rasn::error::DecodeErrorKind;
use rasn_ldap::{LdapMessage, ProtocolOp};
use std::{
    fmt::Display,
    io::{ErrorKind, Read, Write},
    net::{TcpStream, ToSocketAddrs},
    time::Duration,
};

use crate::bind::Unbound;

pub const LDAP_PORT: u16 = 389;
pub const LDAPS_PORT: u16 = 636;

/// Re-exports from native-tls necessary for the compatibility methods
#[cfg(feature = "native-tls")]
pub mod native_tls;
#[cfg(feature = "rustls")]
pub mod rustls;

pub mod bind;
pub mod search;
mod unbind;

pub struct LdapConnection<Stream, BindState = Unbound>
where
    Stream: Read + Write,
{
    stream: Stream,
    next_message_id: u32,
    state: BindState,
}

// Could technically be on generic T but would have to include
// type annotations then
impl LdapConnection<TcpStream, Unbound> {
    pub fn connect(addr: impl ToSocketAddrs) -> Result<LdapConnection<TcpStream, Unbound>, std::io::Error> {
        let stream = TcpStream::connect(addr)?;
        stream.set_read_timeout(Some(Duration::from_secs(10)))?;
        Ok(LdapConnection::new_unbound(stream))
    }
}
impl<Stream: Read + Write> LdapConnection<Stream, Unbound> {
    /// Start an LDAP connection over a custom stream.
    ///
    /// If `Stream` is safe for transmitting passwords in cleartext, e.g. because it's not interceptable
    /// or encrypted, the `Safe` trait will enable safe binding operations
    pub fn new_unbound(stream: Stream) -> LdapConnection<Stream, Unbound> {
        LdapConnection {
            stream,
            next_message_id: 1,
            state: Unbound { _priv: () },
        }
    }
}

impl<Stream: Read + Write, T> LdapConnection<Stream, T> {
    fn get_and_increase_message_id(&mut self) -> u32 {
        let next = self.next_message_id;
        self.next_message_id += 1;
        next
    }
    fn send_single_message(
        &mut self,
        protocol_op: ProtocolOp,
        _controls: Option<()>,
    ) -> Result<ProtocolOp, MessageError> {
        let message_id = self.get_and_increase_message_id();
        let message = LdapMessage::new(message_id, protocol_op);
        let encoded = rasn::ber::encode(&message).expect("Failed to encode BER message");
        self.stream.write_all(&encoded).map_err(MessageError::Io)?;
        let mut buf = Vec::new();
        let mut temp_buffer = [0u8; 2048];
        loop {
            match self.stream.read(&mut temp_buffer).map_err(MessageError::Io)? {
                0 => {
                    return Err(MessageError::Io(std::io::Error::new(
                        ErrorKind::ConnectionReset,
                        "connection closed",
                    )));
                }
                n => {
                    buf.extend_from_slice(&temp_buffer[..n]);
                    match rasn::ber::decode::<LdapMessage>(&buf) {
                        Ok(res) => {
                            if res.message_id != message_id {
                                return Err(MessageError::UnsolicitedResponse);
                            }
                            return Ok(res.protocol_op);
                        }
                        Err(e) if matches!(e.kind.as_ref(), DecodeErrorKind::Incomplete { .. }) => {
                            continue;
                        }
                        Err(e) => return Err(MessageError::Message(e)),
                    }
                }
            };
        }
    }
}

#[derive(Debug)]
enum MessageError {
    Io(std::io::Error),
    Message(rasn::ber::de::DecodeError),
    UnsolicitedResponse,
}

impl std::error::Error for MessageError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Io(io) => Some(io),
            Self::Message(m) => Some(m),
            Self::UnsolicitedResponse => None,
        }
    }
}
impl Display for MessageError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Io(io) => write!(f, "io: {io}"),
            Self::Message(m) => write!(f, "message: {m}"),
            Self::UnsolicitedResponse => write!(f, "Message IDs don't align"),
        }
    }
}
