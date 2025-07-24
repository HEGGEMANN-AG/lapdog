use std::io::{Read, Write};

use rasn_ldap::{AuthenticationChoice, BindRequest, BindResponse, LdapString, ProtocolOp, ResultCode};

use crate::LdapConnection;

pub mod error;
pub use error::{AuthenticatedBindError, SimpleBindError, UnauthenticatedBindError};

/// Allows extraction of the last diagnostics message in a successful bind operation
pub trait Bound {
    fn get_bind_diagnostics_message(&self) -> &str;
}

macro_rules! impl_for_bound {
    ([$($typ:ident),*]) => {
        $(
            /// Typestate of the last successful bind operation on this connection
            pub struct $typ {
                bind_diagnostics_message: Box<str>,
            }
            impl Bound for $typ {
                fn get_bind_diagnostics_message(&self) -> &str {
                    &self.bind_diagnostics_message
                }
            }
        )*
    };
}
impl_for_bound!([BoundAnonymously, BoundAuthenticated, BoundUnauthenticated]);
/// No bind operation has been done on this connection
pub struct Unbound {
    pub(crate) _priv: (),
}
/// Marker trait for encrypted streams
/// # Safety
/// This is just an inconvenience to make the user think about whether a stream is using TLS
/// or another encryption mechanism
pub unsafe trait Safe {}
#[cfg(feature = "native-tls")]
unsafe impl<T> Safe for native_tls::TlsStream<T> {}
impl<Stream: Read + Write + Safe, OldBindState> LdapConnection<Stream, OldBindState> {
    /// Binds the connection anonymously, aka without a password or username
    ///
    /// For most servers, this leads to limited privileges
    ///
    /// For unencrypted streams the "unsafe_" version of this function is available
    pub fn bind_simple_anonymously(self) -> Result<LdapConnection<Stream, BoundAnonymously>, SimpleBindError> {
        self.inner_bind_simple_anonymously()
    }
    /// Binds the connection in the unauthenticated mode.
    ///
    /// Default is for servers to reject this, but some may implement privileges for these kinds of connections
    ///
    /// An empty username is invalid, use `bind_simple_anonymously` instead
    ///
    /// For unencrypted streams the "unsafe_" version of this function is available
    pub fn bind_simple_unauthenticated(
        self,
        name: &str,
    ) -> Result<LdapConnection<Stream, BoundUnauthenticated>, UnauthenticatedBindError> {
        self.inner_bind_simple_unauthenticated(name)
    }
    /// Binds the connection with simple auth
    ///
    /// An empty username or password is invalid, use `bind_simple_anonymously` or `bind_simple_unauthenticated` instead
    ///
    /// For unencrypted streams the "unsafe_" version of this function is available
    pub fn bind_simple_authenticated(
        self,
        name: &str,
        password: &[u8],
    ) -> Result<LdapConnection<Stream, BoundAuthenticated>, AuthenticatedBindError> {
        self.inner_bind_simple_authenticated(name, password)
    }
}
impl<Stream: Read + Write, OldBindState> LdapConnection<Stream, OldBindState> {
    /// Binds the connection anonymously, aka without a password or username
    ///
    /// For most servers, this leads to limited privileges
    ///
    /// If you call this, you didn't add TLS or any safety mechanism to this stream and the credentials will be potentially exposed
    #[doc(hidden)]
    pub fn unsafe_bind_simple_anonymously(self) -> Result<LdapConnection<Stream, BoundAnonymously>, SimpleBindError> {
        self.inner_bind_simple_anonymously()
    }
    /// Binds the connection in the unauthenticated mode.
    ///
    /// Default is for servers to reject this, but some may implement privileges for these kinds of connections
    ///
    /// An empty username is invalid, use `bind_simple_anonymously` instead.
    ///
    /// If you call this, you didn't add TLS or any safety mechanism to this stream and the credentials will be potentially exposed
    #[doc(hidden)]
    pub fn unsafe_bind_simple_unauthenticated(
        self,
        name: &str,
    ) -> Result<LdapConnection<Stream, BoundUnauthenticated>, UnauthenticatedBindError> {
        self.inner_bind_simple_unauthenticated(name)
    }
    /// Binds the connection with simple auth
    ///
    /// An empty username or password is invalid, use `bind_simple_anonymously` or `bind_simple_unauthenticated` instead
    ///
    /// If you call this, you didn't add TLS or any safety mechanism to this stream and the credentials will be potentially exposed
    #[doc(hidden)]
    pub fn unsafe_bind_simple_authenticated(
        self,
        name: &str,
        password: &[u8],
    ) -> Result<LdapConnection<Stream, BoundAuthenticated>, AuthenticatedBindError> {
        self.inner_bind_simple_authenticated(name, password)
    }
}

// The LDAP standard recommends to implement these different types of bind explicitly, so I'm doing it this way
impl<Stream: Read + Write, OldBindState> LdapConnection<Stream, OldBindState> {
    fn inner_bind_simple_anonymously(self) -> Result<LdapConnection<Stream, BoundAnonymously>, SimpleBindError> {
        self.bind_simple_raw("", &[], |bind_diagnostics_message| BoundAnonymously {
            bind_diagnostics_message,
        })
    }
    fn inner_bind_simple_unauthenticated(
        self,
        name: &str,
    ) -> Result<LdapConnection<Stream, BoundUnauthenticated>, UnauthenticatedBindError> {
        if name.is_empty() {
            return Err(UnauthenticatedBindError::EmptyUsername);
        }
        self.bind_simple_raw(name, &[], |bind_diagnostics_message| BoundUnauthenticated {
            bind_diagnostics_message,
        })
        .map_err(UnauthenticatedBindError::Bind)
    }
    fn inner_bind_simple_authenticated(
        self,
        name: &str,
        password: &[u8],
    ) -> Result<LdapConnection<Stream, BoundAuthenticated>, AuthenticatedBindError> {
        if password.is_empty() {
            return Err(AuthenticatedBindError::EmptyPassword);
        }
        if name.is_empty() {
            return Err(AuthenticatedBindError::EmptyUsername);
        }
        self.bind_simple_raw(name, password, |bind_diagnostics_message| BoundAuthenticated {
            bind_diagnostics_message,
        })
        .map_err(AuthenticatedBindError::Bind)
    }
    /// Internal method with name and password
    ///
    /// Not exposed externally due to different behaviour depending on bind.
    /// Takes the connection to guarantee disconnect when the bind should fail.
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
                _ => return Err(SimpleBindError::MalformedResponseNotBindResponse),
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
    pub fn get_bind_diagnostics_message(&self) -> &str {
        self.state.get_bind_diagnostics_message()
    }
}
