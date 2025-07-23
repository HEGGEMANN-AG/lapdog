use std::io::{Read, Write};

use rasn_ldap::{LdapMessage, ProtocolOp, UnbindRequest};

use crate::LdapConnection;

impl<Stream, Bind> LdapConnection<Stream, Bind>
where
    Stream: Read + Write,
{
    pub fn unbind(mut self) -> Result<(), UnbindError> {
        let proto = ProtocolOp::UnbindRequest(UnbindRequest {});
        let encoded = rasn::ber::encode(&LdapMessage::new(self.get_and_increase_message_id(), proto))
            .expect("Failed to encode BER message");
        self.stream.write_all(&encoded).map_err(UnbindError)
    }
}

#[derive(Debug)]
pub struct UnbindError(std::io::Error);
impl std::error::Error for UnbindError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        Some(&self.0)
    }
}
impl std::fmt::Display for UnbindError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Failed to unbind: {}", self.0)
    }
}
