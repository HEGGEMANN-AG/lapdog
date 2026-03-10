use std::io::{Read, Write};

mod auth;
mod bind;
mod integer;
mod length;
mod message;
mod result;
mod tag;

pub use message::{Message, RequestMessage, ResponseProtocolOp};

const LDAP_VERSION: i32 = 3;

trait ReadExt: Read {
    fn read_single_byte(&mut self) -> std::io::Result<u8> {
        let mut b = 0;
        self.read_exact(std::slice::from_mut(&mut b))?;
        Ok(b)
    }
}
impl<R: Read> ReadExt for R {}

trait WriteExt: Write {
    fn write_single_byte(&mut self, b: u8) -> std::io::Result<()> {
        self.write_all(&[b])
    }
    fn write_ber_integer(&mut self, i: i32) -> std::io::Result<()> {
        crate::integer::write_integer(i, self)?;
        Ok(())
    }
}
impl<W: Write> WriteExt for W {}

#[cfg(test)]
mod test {
    #[test]
    #[cfg(feature = "native-tls")]
    fn bind_simple() {
        use std::{io::Write, net::TcpStream, num::NonZero};

        use kenobi::{
            client::{ClientBuilder, StepOut},
            cred::Credentials,
        };

        use crate::{
            Message, ResponseProtocolOp,
            auth::{Authentication, SaslMechanism},
            message::{RequestMessage, RequestProtocolOp, ResponseMessage},
        };
        use native_tls::TlsConnector;
        let server = std::env::var("LAPDOG2_SERVER").unwrap();
        let target_spn = std::env::var("LAPDOG2_TARGET_SPN").ok();
        let tcp = TcpStream::connect(&server).unwrap();
        let tls_conf = TlsConnector::new().unwrap();
        let mut tcp = tls_conf
            .connect(server.split_once(':').unwrap().0, tcp)
            .unwrap();

        let request_with_token = |message_id: i32, token: Option<&[u8]>| RequestMessage {
            message_id: NonZero::new(message_id),
            protocol_op: RequestProtocolOp::Bind {
                authentication: Authentication::Sasl {
                    mechanism: SaslMechanism::GssAPI,
                    credentials: token.map(|t| t.to_vec()),
                },
            },
        };
        let cred = Credentials::outbound(None).unwrap();
        let client = ClientBuilder::new_from_credentials(&cred, target_spn.as_deref())
            .bind_to_channel(&tcp)
            .unwrap()
            .deny_signing()
            .initialize();
        let pending = match client {
            StepOut::Pending(p) => p,
            StepOut::Finished(_client_context) => unreachable!(),
        };

        let credentials = pending.next_token();
        let prot = request_with_token(1, Some(credentials));
        prot.write_to(&mut tcp).unwrap();
        tcp.flush().unwrap();

        let Message {
            protocol_op:
                ResponseProtocolOp::Bind {
                    server_sasl_creds: Some(server_sasl_creds),
                },
            ..
        } = ResponseMessage::read_from(&mut tcp).unwrap()
        else {
            panic!("Unexpected message");
        };

        let client = match pending.step(&server_sasl_creds) {
            StepOut::Finished(c) => {
                let second_message = request_with_token(2, c.last_token());
                second_message.write_to(&mut tcp).unwrap();
                tcp.flush().unwrap();
                c
            }
            StepOut::Pending(_) => panic!("Still pending!"),
        };

        let Message {
            protocol_op: ResponseProtocolOp::Bind { server_sasl_creds },
            ..
        } = ResponseMessage::read_from(&mut tcp).unwrap()
        else {
            panic!()
        };
        let empty_message = request_with_token(3, server_sasl_creds.as_deref());
        empty_message.write_to(&mut tcp).unwrap();
        std::thread::sleep(std::time::Duration::from_secs(1));
        todo!()
    }
}
