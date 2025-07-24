use std::io::{Read, Write};

use rasn_ldap::{AuthenticationChoice, BindRequest, BindResponse, LdapString, ProtocolOp, ResultCode};

use crate::LdapConnection;

pub mod error;
pub use error::{MaybeEmptyPassword, MaybeEmptyUsername, SimpleBindError};

pub trait Bound {
    fn bind_diagnostics_message(&self) -> &str;
}
macro_rules! impl_for_bound {
    ($typ:ident) => {
        pub struct $typ {
            bind_diagnostics_message: Box<str>,
        }
        impl Bound for $typ {
            fn bind_diagnostics_message(&self) -> &str {
                &self.bind_diagnostics_message
            }
        }
    };
}
impl_for_bound!(BoundAnonymously);
impl_for_bound!(BoundAuthenticated);
impl_for_bound!(BoundUnauthenticated);
pub struct Unbound {
    pub(crate) _priv: (),
}

impl<Stream: Read + Write> LdapConnection<Stream, Unbound> {
    pub fn bind_simple_anonymously(self) -> Result<LdapConnection<Stream, BoundAnonymously>, SimpleBindError> {
        self.bind_simple_raw("", &[], |bind_diagnostics_message| BoundAnonymously {
            bind_diagnostics_message,
        })
    }
    pub fn bind_simple_unauthenticated(
        self,
        name: &str,
    ) -> Result<LdapConnection<Stream, BoundUnauthenticated>, MaybeEmptyUsername<SimpleBindError>> {
        if name.is_empty() {
            return Err(MaybeEmptyUsername::EmptyUsername);
        }
        Ok(
            self.bind_simple_raw(name, &[], |bind_diagnostics_message| BoundUnauthenticated {
                bind_diagnostics_message,
            })?,
        )
    }
    pub fn bind_simple_authenticated(
        self,
        name: &str,
        password: &[u8],
    ) -> Result<LdapConnection<Stream, BoundAuthenticated>, MaybeEmptyPassword<MaybeEmptyUsername<SimpleBindError>>>
    {
        if password.is_empty() {
            return Err(MaybeEmptyPassword::EmptyPassword);
        }
        if name.is_empty() {
            return Err(MaybeEmptyUsername::EmptyUsername.into());
        }
        self.bind_simple_raw(name, password, |bind_diagnostics_message| BoundAuthenticated {
            bind_diagnostics_message,
        })
        .map_err(|e| MaybeEmptyPassword::Other(MaybeEmptyUsername::Other(e)))
    }
    // Takes the connection to guarantee disconnect when the bind should fail
    fn bind_simple_raw<BindState>(
        mut self,
        name: &str,
        password: &[u8],
        bind: impl FnOnce(Box<str>) -> BindState,
    ) -> Result<LdapConnection<Stream, BindState>, SimpleBindError> {
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
                state: bind(message),
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
impl<Stream: Read + Write, B: Bound> LdapConnection<Stream, B> {
    pub fn bind_diagnostics_message(&self) -> &str {
        self.state.bind_diagnostics_message()
    }
}
