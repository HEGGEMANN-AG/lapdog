use std::{error::Error, fmt::Display};

use rasn::error::DecodeError;
use rasn_ldap::LdapString;

use crate::MessageError;

impl From<MessageError> for SimpleBindError {
    fn from(value: MessageError) -> Self {
        match value {
            MessageError::Io(io) => SimpleBindError::IoError(io),
            MessageError::Message(m) => SimpleBindError::MalformedResponse(m),
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
    MalformedResponseNotBindResponse,
    /// Server sent non-BER message
    MalformedResponse(DecodeError),
    /// Server send SASL creds for a non-sasl method
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
            Self::MalformedResponse(m) => Some(m),
            _ => None,
        }
    }
}
impl Display for SimpleBindError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::MalformedResponseNotBindResponse => write!(f, "Server sent non-bind response message"),
            Self::MalformedResponse(message) => write!(f, "Server sent invalid response: {message}"),
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

#[derive(Debug)]
pub enum MaybeEmptyUsername<E> {
    EmptyUsername,
    Other(E),
}
impl<E: Error + 'static> Error for MaybeEmptyUsername<E> {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        if let Self::Other(o) = self { Some(o) } else { None }
    }
}
impl<E: Display> Display for MaybeEmptyUsername<E> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Other(o) => write!(f, "{o}"),
            Self::EmptyUsername => write!(f, "Name cannot be empty on an non-anonymous bind"),
        }
    }
}
impl<E> From<E> for MaybeEmptyUsername<E> {
    fn from(value: E) -> Self {
        MaybeEmptyUsername::Other(value)
    }
}
impl<E> MaybeEmptyUsername<E> {
    pub fn into_inner(self) -> Option<E> {
        match self {
            Self::Other(o) => Some(o),
            Self::EmptyUsername => None,
        }
    }
}
#[derive(Debug)]
pub enum MaybeEmptyPassword<E> {
    EmptyPassword,
    Other(E),
}
impl<E: Error + 'static> Error for MaybeEmptyPassword<E> {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        if let Self::Other(o) = self { Some(o) } else { None }
    }
}
impl<E: Display> Display for MaybeEmptyPassword<E> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Other(o) => write!(f, "{o}"),
            Self::EmptyPassword => write!(f, "Password cannot be empty on an authenticated bind"),
        }
    }
}
impl<E> From<E> for MaybeEmptyPassword<E> {
    fn from(value: E) -> Self {
        MaybeEmptyPassword::Other(value)
    }
}
impl<E> MaybeEmptyPassword<E> {
    pub fn into_inner(self) -> Option<E> {
        match self {
            Self::Other(o) => Some(o),
            Self::EmptyPassword => None,
        }
    }
}
