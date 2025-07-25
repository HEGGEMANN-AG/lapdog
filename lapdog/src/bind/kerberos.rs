use std::io::{Read, Write};

use cross_krb5::{ClientCtx, InitiateFlags, Step};
use rasn_ldap::{AuthenticationChoice, BindRequest, BindResponse, ProtocolOp, ResultCode, SaslCredentials};

use crate::{LdapConnection, MessageError};

pub struct BoundKerberos {
    _kerberos: ClientCtx,
}

impl<Stream: Read + Write, BindState> LdapConnection<Stream, BindState> {
    pub fn bind_kerberos(
        mut self,
        service_principal: &str,
    ) -> Result<LdapConnection<Stream, BoundKerberos>, BindKerberosError> {
        let (mut ctx, msg) = ClientCtx::new(InitiateFlags::empty(), None, service_principal, None).unwrap();
        let mut msg = msg.to_vec();
        loop {
            ctx = match ctx.step(&msg).unwrap() {
                Step::Finished((_kerberos, Some(ticket))) => {
                    let BindResponse {
                        result_code,
                        diagnostic_message,
                        server_sasl_creds,
                        ..
                    } = self.send_kerberos_token_msg(&ticket)?;
                    if result_code == ResultCode::Success {
                        return Ok(LdapConnection {
                            stream: self.stream,
                            next_message_id: self.next_message_id,
                            state: BoundKerberos { _kerberos },
                        });
                    }
                    unimplemented!()
                }
                Step::Continue((pending, ticket)) => {
                    let BindResponse { server_sasl_creds, .. } = self.send_kerberos_token_msg(&ticket)?;
                    msg = server_sasl_creds.unwrap().to_vec();
                    pending
                }
                Step::Finished((_, _)) => unimplemented!(),
            }
        }
    }
    fn send_kerberos_token_msg(&mut self, token: &[u8]) -> Result<BindResponse, BindKerberosError> {
        let sasl = SaslCredentials::new("GSSAPI".into(), Some(token.to_vec().into()));
        let message = BindRequest::new(3, "".into(), AuthenticationChoice::Sasl(sasl));
        let op = ProtocolOp::BindRequest(message);
        match self.send_single_message(op, None) {
            Ok(ProtocolOp::BindResponse(b)) => Ok(b),
            Ok(_) => Err(BindKerberosError::NonBindResponseProtocolOp),
            Err(MessageError::Io(io)) => Err(BindKerberosError::Io(io)),
            Err(MessageError::Message(dec)) => Err(BindKerberosError::Decode(dec)),
        }
    }
}
#[derive(Debug)]
pub enum BindKerberosError {
    NonBindResponseProtocolOp,
    Io(std::io::Error),
    Decode(rasn::ber::de::DecodeError),
}
