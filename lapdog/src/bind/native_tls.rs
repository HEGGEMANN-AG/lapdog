use rasn_ldap::{AuthenticationChoice, BindRequest, BindResponse, LdapString, ProtocolOp, ResultCode, SaslCredentials};

use crate::{LdapConnection, MessageError};

unsafe impl<T> super::Safe for native_tls::TlsStream<T> {}
super::impl_bound!([BoundNativeTls]);

impl<Stream: std::io::Read + std::io::Write, BindState> LdapConnection<native_tls::TlsStream<Stream>, BindState> {
    pub fn sasl_external_bind(
        mut self,
        auth_z_id: &str,
    ) -> Result<LdapConnection<native_tls::TlsStream<Stream>, BoundNativeTls>, SaslExternalBindError> {
        let auth = AuthenticationChoice::Sasl(SaslCredentials::new("EXTERNAL".into(), None));
        let message = ProtocolOp::BindRequest(BindRequest::new(3, auth_z_id.into(), auth));
        let ProtocolOp::BindResponse(BindResponse {
            result_code,
            diagnostic_message: LdapString(diagnostic_message),
            ..
        }) = self.send_single_message(message, None).map_err(|e| match e {
            MessageError::Io(io) => SaslExternalBindError::Io(io),
            MessageError::Message(dec) => SaslExternalBindError::Decode(dec),
        })?
        else {
            return Err(SaslExternalBindError::InvalidProtocolOp);
        };
        match result_code {
            ResultCode::Success => Ok(LdapConnection {
                stream: self.stream,
                next_message_id: self.next_message_id,
                state: BoundNativeTls::new(diagnostic_message.into_boxed_str()),
            }),
            _ => unimplemented!(),
        }
    }
}

#[derive(Debug)]
pub enum SaslExternalBindError {
    Io(std::io::Error),
    Decode(rasn::ber::de::DecodeError),
    InvalidProtocolOp,
}
impl std::error::Error for SaslExternalBindError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Decode(dec) => Some(dec),
            Self::Io(io) => Some(io),
            Self::InvalidProtocolOp => None,
        }
    }
}
impl std::fmt::Display for SaslExternalBindError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Decode(d) => write!(f, "Failed to decode message: {d}"),
            Self::Io(io) => write!(f, "IO error: {io}"),
            Self::InvalidProtocolOp => write!(f, "server sent an invalid Protocol op"),
        }
    }
}
