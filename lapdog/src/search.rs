use std::{
    error::Error,
    fmt::Display,
    io::{ErrorKind, Read, Write},
    marker::PhantomData,
};

use crate::LdapConnection;
#[cfg(feature = "derive")]
pub use lapdog_derive::Entry;
use rasn::error::DecodeError;
use rasn_ldap::{
    Filter, LdapMessage, LdapResult, LdapString, PartialAttribute, ProtocolOp, ResultCode, SearchRequest,
    SearchRequestDerefAliases, SearchRequestScope, SearchResultDone, SearchResultEntry, SearchResultReference,
};

#[cfg(feature = "from_octets")]
mod impl_traits;

impl<T> LdapConnection<T> {
    pub fn search<'connection, Output>(
        &'connection mut self,
        base: &str,
        scope: SearchRequestScope,
        deref_aliases: SearchRequestDerefAliases,
        filter: Filter,
    ) -> Result<SearchResults<'connection, T, Output>, std::io::Error>
    where
        Output: FromEntry,
    {
        let attributes: Vec<LdapString> = match <Output as FromEntry>::attributes() {
            None => vec!["*".into()],
            Some(iter) => iter.map(|x| x.to_string().into()).collect(),
        };
        let protocol = ProtocolOp::SearchRequest(SearchRequest::new(
            base.into(),
            scope,
            deref_aliases,
            0,
            0,
            false,
            filter,
            attributes,
        ));
        let encoded = rasn::ber::encode(&LdapMessage::new(self.get_and_increase_message_id(), protocol))
            .expect("Failed to encode BER message");
        self.tcp.write_all(&encoded)?;
        Ok(SearchResults::new(self))
    }
}

#[derive(Debug)]
#[non_exhaustive]
pub enum SearchError {
    Io(std::io::Error),
}
impl Error for SearchError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Io(io) => Some(io),
        }
    }
}
impl Display for SearchError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Io(io) => write!(f, "Failed to write to message: {io}"),
        }
    }
}

pub trait FromEntry: Sized {
    fn from_entry(entry: RawEntry) -> Result<Self, FailedToGetFromEntry>;

    fn attributes() -> Option<impl Iterator<Item = &'static str>> {
        None::<std::iter::Empty<&str>>
    }
}
#[derive(Debug)]
pub enum FailedToGetFromEntry {
    MissingField(&'static str),
    FailedToParseField(&'static str, Box<dyn Error>),
}
impl Error for FailedToGetFromEntry {}
impl Display for FailedToGetFromEntry {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::MissingField(field) => write!(f, "Server did not send field \"{field}\""),
            Self::FailedToParseField(field, error) => write!(f, "Failed to parse field \"{field}\": {error}"),
        }
    }
}

#[cfg(feature = "from_octets")]
pub trait FromOctetString: Sized {
    type Err: Error;
    fn from_octet_string(bytes: &[u8]) -> Result<Self, Self::Err>;
}

#[cfg(feature = "from_octets")]
pub trait FromMultipleOctetStrings: Sized {
    type Err: Error;
    fn from_multiple_octet_strings<'a>(values: impl Iterator<Item = &'a [u8]>) -> Result<Self, Self::Err>;
}

pub struct SearchResults<'connection, T, Output> {
    connection: &'connection mut LdapConnection<T>,
    remainder: Option<Vec<u8>>,
    done: bool,
    _out: PhantomData<Output>,
}
impl<T, Output> SearchResults<'_, T, Output> {
    fn new(connection: &mut LdapConnection<T>) -> SearchResults<'_, T, Output> {
        SearchResults {
            connection,
            remainder: None,
            done: false,
            _out: PhantomData,
        }
    }
}
const TEMP_BUFFER_LENGTH: usize = 1024;
impl<'connection, T, Output> Iterator for SearchResults<'connection, T, Output>
where
    Output: FromEntry,
{
    type Item = Result<Output, SearchResultError>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.done {
            return None;
        }
        let mut buf = Vec::with_capacity(2048);
        let mut temp_buffer = [0u8; TEMP_BUFFER_LENGTH];
        if let Some(rem) = &self.remainder {
            buf.extend(rem);
        }
        loop {
            if !buf.is_empty() {
                match rasn::ber::decode_with_remainder::<LdapMessage>(&buf) {
                    Ok((LdapMessage { protocol_op, .. }, remainder)) => {
                        let new_remainder = self.remainder.get_or_insert(Vec::new());
                        new_remainder.clear();
                        new_remainder.extend(remainder);
                        buf.clear();
                        match protocol_op {
                            ProtocolOp::SearchResEntry(SearchResultEntry {
                                object_name: LdapString(object_name),
                                attributes,
                                ..
                            }) => {
                                let attributes = attributes
                                    .into_iter()
                                    .map(
                                        |PartialAttribute {
                                             r#type: LdapString(r#type),
                                             vals,
                                             ..
                                         }| Attribute {
                                            r#type,
                                            values: vals.to_vec().iter().map(|o| o.to_vec()).collect(),
                                        },
                                    )
                                    .collect();
                                let entry = RawEntry {
                                    object_name,
                                    attributes,
                                };
                                return Some(Output::from_entry(entry).map_err(Into::into));
                            }
                            ProtocolOp::SearchResDone(SearchResultDone(LdapResult {
                                result_code,
                                matched_dn,
                                diagnostic_message,
                                ..
                            })) => {
                                self.done = true;
                                let diagnostic_message = diagnostic_message.0.into_boxed_str();
                                let matched_dn = matched_dn.0.into_boxed_str();
                                match result_code {
                                    ResultCode::Success => return None,
                                    ResultCode::NoSuchObject => {
                                        return Some(Err(SearchResultError::NoSuchObject(
                                            matched_dn,
                                            diagnostic_message,
                                        )));
                                    }
                                    ResultCode::OperationsError => {
                                        return Some(Err(SearchResultError::OperationsError(diagnostic_message)));
                                    }
                                    result_code => Some(Err::<Output, _>(SearchResultError::Other {
                                        result_code,
                                        diagnostic_message,
                                        matched_dn,
                                    })),
                                }
                            }
                            ProtocolOp::SearchResRef(SearchResultReference(_)) => continue,
                            po => return Some(Err(SearchResultError::InvalidLdapMessage(po))),
                        };
                    }
                    Err(rasn::ber::de::DecodeError { kind, .. })
                        if matches!(*kind, rasn::ber::de::DecodeErrorKind::Incomplete { .. }) => {}
                    Err(e) => return Some(Err(SearchResultError::MalformedLdapMessage(e))),
                }
            }
            match self.connection.tcp.read(&mut temp_buffer) {
                Ok(0) => {
                    return Some(Err(SearchResultError::Io(std::io::Error::new(
                        ErrorKind::ConnectionReset,
                        "connection closed",
                    ))));
                }
                Ok(n) => {
                    buf.extend_from_slice(&temp_buffer[..n]);
                    &buf
                }
                Err(e) => return Some(Err(SearchResultError::Io(e))),
            };
        }
    }
}

#[derive(Debug)]
pub struct RawEntry {
    pub object_name: String,
    pub attributes: Vec<Attribute>,
}
#[derive(Debug)]
pub struct Attribute {
    pub r#type: String,
    pub values: Vec<Vec<u8>>,
}
impl FromEntry for RawEntry {
    fn from_entry(entry: RawEntry) -> Result<Self, FailedToGetFromEntry> {
        Ok(entry)
    }
}

#[derive(Debug)]
pub enum SearchResultError {
    /// Message sent violated ASN1/BER encoding
    MalformedLdapMessage(DecodeError),
    /// Message was not a valid search response message
    InvalidLdapMessage(ProtocolOp),
    OperationsError(Box<str>),
    NoSuchObject(Box<str>, Box<str>),
    InsufficientAccessRights(Box<str>),
    TimeLimitExceeded(Box<str>),
    SizeLimitExceeded(Box<str>),
    FilterError(Box<str>),
    MissingField(&'static str),
    FailedToParseField(&'static str, Box<dyn Error + 'static>),
    Io(std::io::Error),
    Other {
        result_code: ResultCode,
        diagnostic_message: Box<str>,
        matched_dn: Box<str>,
    },
}
impl Error for SearchResultError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Io(io) => Some(io),
            Self::MalformedLdapMessage(de) => Some(de),
            Self::FailedToParseField(_, b) => Some(b.as_ref()),
            _ => None,
        }
    }
}
impl Display for SearchResultError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Io(io) => write!(f, "io error: {io}"),
            Self::InvalidLdapMessage(_ro) => write!(f, "Server sent non-search response"),
            Self::MissingField(field) => write!(f, "Server did not sent field \"{field}\""),
            Self::FailedToParseField(field, err) => write!(f, "Failed to parse field \"{field}\": {err}"),
            Self::MalformedLdapMessage(mal) => write!(f, "couldn't decode server response: {mal}"),
            Self::NoSuchObject(matched, no) => write!(f, "No such object: matched_dn: {matched}, message: {no}"),
            Self::InsufficientAccessRights(iar) => write!(f, "Insufficient access rights: {iar}"),
            Self::TimeLimitExceeded(le) => write!(f, "Time limit exceeded: {le}"),
            Self::SizeLimitExceeded(le) => write!(f, "Size limit exceeded: {le}"),
            Self::OperationsError(oe) => write!(f, "Server operations error: {oe}"),
            Self::FilterError(fe) => write!(f, "Filter error: {fe}"),
            Self::Other {
                result_code,
                diagnostic_message,
                matched_dn,
            } => write!(
                f,
                "Miscellaneous LDAP error: code: {}, message: {diagnostic_message}, matched_dn: {matched_dn}",
                *result_code as u32
            ),
        }
    }
}
impl From<FailedToGetFromEntry> for SearchResultError {
    fn from(value: FailedToGetFromEntry) -> Self {
        match value {
            FailedToGetFromEntry::MissingField(f) => Self::MissingField(f),
            FailedToGetFromEntry::FailedToParseField(field, err) => Self::FailedToParseField(field, err),
        }
    }
}
