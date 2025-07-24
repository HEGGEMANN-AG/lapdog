use rasn_ldap::{LdapMessage, ProtocolOp};
use std::{
    fmt::Display,
    io::{ErrorKind, Read, Write},
    net::{TcpStream, ToSocketAddrs},
};

use crate::bind::Unbound;

/// Re-exports from native-tls necessary for the compatibility methods
#[cfg(feature = "native-tls")]
pub mod native_tls;

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
        Ok(LdapConnection::new_unbound(stream))
    }
}
impl<Stream: Read + Write> LdapConnection<Stream, Unbound> {
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
        let message = LdapMessage::new(self.get_and_increase_message_id(), protocol_op);
        let encoded = rasn::ber::encode(&message).expect("Failed to encode BER message");
        self.stream.write_all(&encoded).map_err(MessageError::Io)?;
        let mut buf = Vec::new();
        let mut temp_buffer = [0u8; 1024];
        let response_msg = match self.stream.read(&mut temp_buffer).map_err(MessageError::Io)? {
            0 => {
                return Err(MessageError::Io(std::io::Error::new(
                    ErrorKind::ConnectionReset,
                    "connection closed",
                )));
            }
            n => {
                buf.extend_from_slice(&temp_buffer[..n]);
                rasn::ber::decode::<LdapMessage>(&buf).map_err(MessageError::Message)?
            }
        };
        Ok(response_msg.protocol_op)
    }
}

#[derive(Debug)]
enum MessageError {
    Io(std::io::Error),
    Message(rasn::ber::de::DecodeError),
}

impl std::error::Error for MessageError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        Some(match self {
            Self::Io(io) => io,
            Self::Message(m) => m,
        })
    }
}
impl Display for MessageError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Io(io) => write!(f, "io: {io}"),
            Self::Message(m) => write!(f, "message: {m}"),
        }
    }
}
