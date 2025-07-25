use std::io::{Read, Write};

use rasn_ldap::{AuthenticationChoice, BindRequest, BindResponse, LdapString, ProtocolOp, ResultCode};

use crate::LdapConnection;

pub mod error;
pub use error::{AuthenticatedBindError, SimpleBindError, UnauthenticatedBindError};
#[cfg(feature = "kerberos")]
pub mod kerberos;
#[cfg(feature = "native-tls")]
pub mod native_tls;
#[cfg(feature = "rustls")]
pub mod rustls;

/// Allows extraction of the last diagnostics message in a successful bind operation
pub trait Bound {
    fn get_bind_diagnostics_message(&self) -> &str;
}
macro_rules! impl_bound {
    ([$($typ:ident),*]) => {
        $(
            impl_bound!($typ);
        )*
    };
    ($typ:ident) => {
        /// Typestate of the last successful bind operation on this connection
        pub struct $typ {
            bind_diagnostics_message: Box<str>,
        }
        impl $typ {
            pub(crate) fn new(bind_diagnostics_message: Box<str>) -> Self {
                Self { bind_diagnostics_message }
            }
        }
        impl crate::bind::Bound for $typ {
            fn get_bind_diagnostics_message(&self) -> &str {
                &self.bind_diagnostics_message
            }
        }
    };
}
pub(crate) use impl_bound;
impl_bound!([BoundAnonymously, BoundAuthenticated, BoundUnauthenticated]);
/// No bind operation has been done on this connection
pub struct Unbound {
    pub(crate) _priv: (),
}
/// Marker trait for encrypted streams
/// # Safety
/// This is just an inconvenience to make the user think about whether a stream is using TLS
/// or another encryption mechanism
pub unsafe trait Safe {}

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
        self.bind_simple_raw("", &[], BoundAnonymously::new)
    }
    fn inner_bind_simple_unauthenticated(
        self,
        name: &str,
    ) -> Result<LdapConnection<Stream, BoundUnauthenticated>, UnauthenticatedBindError> {
        if name.is_empty() {
            return Err(UnauthenticatedBindError::EmptyUsername);
        }
        self.bind_simple_raw(name, &[], BoundUnauthenticated::new)
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
        self.bind_simple_raw(name, password, BoundAuthenticated::new)
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

#[cfg(any(feature = "rustls", feature = "native-tls"))]
impl<Stream: std::io::Read + std::io::Write + Safe, BindState> LdapConnection<Stream, BindState> {
    fn internal_sasl_external_bind<NewBoundState>(
        mut self,
        auth_z_id: &str,
        bound_factory: impl FnOnce(Box<str>) -> NewBoundState,
    ) -> Result<LdapConnection<Stream, NewBoundState>, SaslExternalBindError> {
        use crate::MessageError;

        let auth = AuthenticationChoice::Sasl(rasn_ldap::SaslCredentials::new("EXTERNAL".into(), None));
        let message = ProtocolOp::BindRequest(BindRequest::new(3, auth_z_id.into(), auth));
        let ProtocolOp::BindResponse(BindResponse {
            result_code,
            diagnostic_message: LdapString(diagnostic_message),
            ..
        }) = self.send_single_message(message, None).map_err(|e| match e {
            MessageError::Io(io) => SaslExternalBindError::Io(io),
            MessageError::Message(dec) => SaslExternalBindError::Decode(dec),
            MessageError::UnsolicitedResponse => SaslExternalBindError::InvalidMessage,
        })?
        else {
            return Err(SaslExternalBindError::InvalidMessage);
        };
        match result_code {
            ResultCode::Success => Ok(LdapConnection {
                stream: self.stream,
                next_message_id: self.next_message_id,
                state: bound_factory(diagnostic_message.into_boxed_str()),
            }),
            _ => unimplemented!(),
        }
    }
}

#[derive(Debug)]
pub enum SaslExternalBindError {
    Io(std::io::Error),
    Decode(rasn::ber::de::DecodeError),
    InvalidMessage,
}
impl std::error::Error for SaslExternalBindError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Decode(dec) => Some(dec),
            Self::Io(io) => Some(io),
            Self::InvalidMessage => None,
        }
    }
}
impl std::fmt::Display for SaslExternalBindError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Decode(d) => write!(f, "Failed to decode message: {d}"),
            Self::Io(io) => write!(f, "IO error: {io}"),
            Self::InvalidMessage => write!(f, "server sent an invalid Protocol op or message ID"),
        }
    }
}

impl<Stream: Read + Write, B: Bound> LdapConnection<Stream, B> {
    pub fn get_bind_diagnostics_message(&self) -> &str {
        self.state.get_bind_diagnostics_message()
    }
}
