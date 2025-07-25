use std::io::{Read, Write};

use cross_krb5::{ClientCtx, InitiateFlags, Step};
use rasn_ldap::{AuthenticationChoice, BindRequest, BindResponse, ProtocolOp, SaslCredentials};

use crate::LdapConnection;

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
            match ctx.step(&msg).unwrap() {
                Step::Finished((_kerberos, Some(ticket))) => {
                    let sasl = SaslCredentials::new("GSSAPI".into(), Some(ticket.to_vec().into()));
                    let message = BindRequest::new(3, "".into(), AuthenticationChoice::Sasl(sasl));
                    let ProtocolOp::BindResponse(br) = self
                        .send_single_message(ProtocolOp::BindRequest(message), None)
                        .unwrap()
                    else {
                        panic!("Not a bind response")
                    };
                    dbg!(br);
                    return Ok(LdapConnection {
                        stream: self.stream,
                        next_message_id: self.next_message_id,
                        state: BoundKerberos { _kerberos },
                    });
                }
                Step::Continue((pending, next_msg)) => {
                    ctx = pending;
                    msg = next_msg.to_vec();
                }
                Step::Finished((_, _)) => unimplemented!(),
            }
        }
    }
}
pub enum BindKerberosError {}
