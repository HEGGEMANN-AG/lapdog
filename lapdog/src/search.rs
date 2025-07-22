use std::{
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

impl<T> LdapConnection<T> {
    pub fn search<'connection, Output>(
        &'connection mut self,
        base: &str,
        scope: SearchRequestScope,
        deref_aliases: SearchRequestDerefAliases,
        filter: Filter,
    ) -> Result<SearchResults<'connection, T, Output>, std::io::Error>
    where
        Output: Entry,
    {
        let attributes: Vec<LdapString> = match <Output as Entry>::attributes() {
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
        let encoded = rasn::ber::encode(&LdapMessage::new(self.get_and_increase_message_id(), protocol)).unwrap();
        self.tcp.write_all(&encoded)?;
        Ok(SearchResults {
            connection: self,
            remainder: None,
            _out: PhantomData,
        })
    }
}

pub trait Entry {
    fn from_entry(entry: RawEntry) -> Result<Self, FailedToGetFromEntry>
    where
        Self: std::marker::Sized;

    fn attributes() -> Option<impl Iterator<Item = &'static str>> {
        None::<std::iter::Empty<&str>>
    }
}
#[derive(Debug)]
pub enum FailedToGetFromEntry {
    MissingField(&'static str),
}
impl std::error::Error for FailedToGetFromEntry {}
impl std::fmt::Display for FailedToGetFromEntry {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::MissingField(field) => write!(f, "Server did not send field \"{field}\""),
        }
    }
}

pub trait FromOctetString {
    fn from_octet_string(bytes: &[u8]) -> Self;
}

impl FromOctetString for String {
    fn from_octet_string(bytes: &[u8]) -> Self {
        String::from_utf8(bytes.to_vec()).unwrap()
    }
}
impl FromOctetString for u32 {
    fn from_octet_string(bytes: &[u8]) -> Self {
        let s = str::from_utf8(bytes).unwrap();
        s.parse().unwrap()
    }
}

pub struct SearchResults<'connection, T, Output> {
    connection: &'connection mut LdapConnection<T>,
    remainder: Option<Vec<u8>>,
    _out: PhantomData<Output>,
}
const TEMP_BUFFER_LENGTH: usize = 1024;
impl<'connection, T, Output> Iterator for SearchResults<'connection, T, Output>
where
    Output: Entry,
{
    type Item = Result<Output, SearchResultError>;

    fn next(&mut self) -> Option<Self::Item> {
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
                            ProtocolOp::SearchResDone(SearchResultDone(LdapResult {
                                result_code: ResultCode::Success,
                                ..
                            })) => return None,
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
impl Entry for RawEntry {
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
    MissingField(&'static str),
    Io(std::io::Error),
}
impl std::error::Error for SearchResultError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Io(io) => Some(io),
            Self::MalformedLdapMessage(de) => Some(de),
            _ => None,
        }
    }
}
impl std::fmt::Display for SearchResultError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Io(io) => write!(f, "io error: {io}"),
            Self::InvalidLdapMessage(_ro) => write!(f, "Server sent non-search response"),
            Self::MissingField(field) => write!(f, "Server did not sent field \"{field}\""),
            Self::MalformedLdapMessage(mal) => write!(f, "couldn't decode server response: {mal}"),
        }
    }
}
impl From<FailedToGetFromEntry> for SearchResultError {
    fn from(value: FailedToGetFromEntry) -> Self {
        match value {
            FailedToGetFromEntry::MissingField(f) => Self::MissingField(f),
        }
    }
}
