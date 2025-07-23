use rasn_ldap::{AuthenticationChoice, BindRequest, BindResponse, LdapMessage, LdapString, ProtocolOp, ResultCode};
use std::{
    fmt::Display,
    io::{ErrorKind, Read, Write},
    net::{TcpStream, ToSocketAddrs},
};

/// Re-exports from native-tls necessary for the compatibility methods
#[cfg(feature = "native-tls")]
pub mod native_tls;

pub mod search;
mod unbind;

pub struct Bound {
    bind_diagnostics_message: Box<str>,
}
pub struct Unbound {
    _priv: (),
}

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
impl<Stream: Read + Write> LdapConnection<Stream, Unbound> {
    // Takes the connection to guarantee disconnect when the bind should fail
    pub fn bind_simple(
        mut self,
        name: &str,
        password: &[u8],
    ) -> Result<LdapConnection<Stream, Bound>, SimpleBindError> {
        let auth = AuthenticationChoice::Simple(password.into());
        let (result_code, message, referral) =
            match self.send_single_message(ProtocolOp::BindRequest(BindRequest::new(3, name.into(), auth)), None)? {
                ProtocolOp::BindResponse(BindResponse {
                    server_sasl_creds: Some(_),
                    ..
                }) => return Err(SimpleBindError::MalformedResponseIncludedSasl),
                ProtocolOp::BindResponse(BindResponse {
                    result_code,
                    diagnostic_message: LdapString(s),
                    referral,
                    ..
                }) => (result_code, s.into_boxed_str(), referral),
                _ => return Err(SimpleBindError::MalformedResponse),
            };
        match result_code {
            ResultCode::Success => Ok(LdapConnection {
                stream: self.stream,
                next_message_id: self.next_message_id,
                state: Bound {
                    bind_diagnostics_message: message,
                },
            }),
            ResultCode::Referral => match referral {
                Some(referrals) => Err(SimpleBindError::Referral { referrals, message }),
                None => Err(SimpleBindError::ReferralWithoutTarget(message)),
            },
            ResultCode::ProtocolError => Err(SimpleBindError::ProtocolError(message)),
            ResultCode::InvalidCredentials => Err(SimpleBindError::InvalidCredentials(message)),
            ResultCode::OperationsError => Err(SimpleBindError::OperationsError(message)),
            ResultCode::Busy | ResultCode::Unavailable => {
                Err(SimpleBindError::ServerUnavailabe(result_code as u32, message))
            }
            ResultCode::InvalidDnSyntax => Err(SimpleBindError::InvalidDn(message)),
            ResultCode::ConfidentialityRequired => Err(SimpleBindError::ConfidentialityRequired(message)),
            ResultCode::InappropriateAuthentication => Err(SimpleBindError::InappropriateAuthentication(message)),
            other => Err(SimpleBindError::Other(other as u32, message)),
        }
    }
}
impl<Stream: Read + Write> LdapConnection<Stream, Bound> {
    pub fn bind_diagnostics_message(&self) -> &str {
        &self.state.bind_diagnostics_message
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
impl From<MessageError> for SimpleBindError {
    fn from(value: MessageError) -> Self {
        match value {
            MessageError::Io(io) => SimpleBindError::IoError(io),
            MessageError::Message(_) => SimpleBindError::MalformedResponse,
        }
    }
}

#[derive(Debug)]
pub enum SimpleBindError {
    /// IO error for writing to the raw TCP stream.
    IoError(std::io::Error),
    /// The Server sent a "referral" response without a target
    ReferralWithoutTarget(Box<str>),
    ProtocolError(Box<str>),
    /// Server sent non-BER message or (incorrectly) included Sasl credits
    MalformedResponse,
    MalformedResponseIncludedSasl,
    Referral {
        referrals: Vec<LdapString>,
        message: Box<str>,
    },
    OperationsError(Box<str>),
    ServerUnavailabe(u32, Box<str>),
    InvalidCredentials(Box<str>),
    InvalidDn(Box<str>),
    ConfidentialityRequired(Box<str>),
    InappropriateAuthentication(Box<str>),
    Other(u32, Box<str>),
}
impl From<std::io::Error> for SimpleBindError {
    fn from(value: std::io::Error) -> Self {
        Self::IoError(value)
    }
}
impl std::error::Error for SimpleBindError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::IoError(io) => Some(io),
            _ => None,
        }
    }
}
impl Display for SimpleBindError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::MalformedResponse => write!(f, "Server sent invalid response"),
            Self::MalformedResponseIncludedSasl => write!(f, "Server sent SASL response credentials"),
            Self::OperationsError(op) => write!(f, "Server operations error: {op}"),
            Self::InvalidDn(message) => write!(f, "Invalid DN: {message}"),
            Self::ConfidentialityRequired(message) => write!(f, "Operation requires confidentiality: {message}"),
            Self::InappropriateAuthentication(message) => write!(f, "Inappropriate authentication: {message}"),
            Self::ServerUnavailabe(code, message) => write!(f, "Server is unavailable (code {code}: {message}"),
            Self::InvalidCredentials(message) => write!(f, "Invalid credentials: {message}"),
            Self::Other(code, message) => write!(f, "bind error: code: {code}, message: \"{message}\""),
            Self::IoError(io) => write!(f, "Io Error: {io}"),
            Self::ReferralWithoutTarget(message) => {
                write!(f, "Server sent referral without target information: {message}")
            }
            Self::Referral { referrals, message } => {
                write!(f, "Server sent referrals: {referrals:?}")?;
                if !message.is_empty() {
                    write!(f, ", {message}")
                } else {
                    Ok(())
                }
            }
            Self::ProtocolError(message) => {
                write!(f, "Protocol version 3 is not supported by the server: {message}")
            }
        }
    }
}
