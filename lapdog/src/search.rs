use std::{
    collections::VecDeque,
    error::Error,
    fmt::Display,
    io::{ErrorKind, Read},
    marker::PhantomData,
};

use crate::{
    LdapConnection, ReceiveMessageError, SendMessageError, WriteExt,
    length::{LengthError, read_length},
    message::RequestProtocolOp,
    parse::ParseLdap,
    read::ReadExt,
    result::ResultCode,
    tag::{
        self, OCTET_STRING, UNIVERSAL_BOOLEAN, UNIVERSAL_ENUMERATED, UNIVERSAL_INTEGER, UNIVERSAL_SEQUENCE,
        UNIVERSAL_SET,
    },
};

#[cfg(feature = "from_octets")]
mod impl_traits;
mod types;
#[cfg(feature = "derive")]
pub use lapdog_derive::Entry;
use tokio::sync::{mpsc::UnboundedReceiver, oneshot::Sender};
pub use types::{DerefPolicy, Filter, MatchingRuleAssertion, Scope};

impl LdapConnection {
    pub async fn search_all(
        &self,
        base_object: &str,
        scope: Scope,
        deref_policy: DerefPolicy,
        filter: Filter<'_>,
    ) -> Result<SearchResults, BeginSearchError> {
        self.search_raw(base_object, scope, deref_policy, filter, vec!["*"])
            .await
    }
    pub async fn search<'a>(
        &self,
        base_object: &str,
        scope: Scope,
        deref_policy: DerefPolicy,
        filter: Filter<'_>,
        attributes: impl IntoIterator<Item = &'a str>,
    ) -> Result<SearchResults, BeginSearchError> {
        self.search_raw(base_object, scope, deref_policy, filter, attributes)
            .await
    }
    pub async fn search_as<Output: FromEntry>(
        &self,
        base_object: &str,
        scope: Scope,
        deref_policy: DerefPolicy,
        filter: Filter<'_>,
    ) -> Result<SearchResults<Output>, BeginSearchError> {
        let attributes = match Output::attributes() {
            None => vec!["*"],
            Some(v) => v.collect(),
        };
        self.search_raw(base_object, scope, deref_policy, filter, attributes)
            .await
    }
    async fn search_raw<'a, Output: FromEntry>(
        &self,
        base_object: &str,
        scope: Scope,
        deref_policy: DerefPolicy,
        filter: Filter<'_>,
        attributes: impl IntoIterator<Item = &'a str>,
    ) -> Result<SearchResults<Output>, BeginSearchError> {
        let attributes: Vec<&str> = attributes.into_iter().collect();
        let proto = RequestProtocolOp::Search {
            base_object,
            scope,
            deref_policy,
            filter,
            attributes: &attributes,
        };
        let (incoming_messages, done) = self
            .send_message(proto)
            .await
            .map_err(BeginSearchError)?
            .into_receiver();
        Ok(SearchResults {
            incoming_messages,
            buffer: Default::default(),
            done: Some(done),
            _e: PhantomData,
        })
    }
}

#[derive(Debug)]
pub struct BeginSearchError(SendMessageError);
impl BeginSearchError {
    pub fn is_disconnect(&self) -> bool {
        match &self.0 {
            SendMessageError::Io(error) if error.kind() == ErrorKind::ConnectionReset => true,
            SendMessageError::ReceiveMessage(ReceiveMessageError::ConnectionClosed) => true,
            _ => false,
        }
    }
}
impl std::error::Error for BeginSearchError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        Some(&self.0)
    }
}
impl Display for BeginSearchError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Failed to dispatch search request: {:?}", self.0)
    }
}

pub struct SearchResults<Output = RawEntry> {
    incoming_messages: UnboundedReceiver<Result<Vec<u8>, ReceiveMessageError>>,
    buffer: VecDeque<u8>,
    done: Option<Sender<()>>,
    _e: PhantomData<Output>,
}
impl<Output: FromEntry> SearchResults<Output> {
    pub async fn next(&mut self) -> Option<Result<SearchResult<Output>, SearchResultError>> {
        let res = if !self.buffer.is_empty() {
            read_search_as::<Output, _>(&mut self.buffer)
        } else {
            match self.incoming_messages.recv().await {
                Some(Ok(body)) => {
                    self.buffer = body.into();
                    read_search_as::<Output, _>(&mut self.buffer)
                }
                Some(Err(ReceiveMessageError::ConnectionClosed)) | None => {
                    if let Some(shutdown) = self.done.take() {
                        let _ = shutdown.send(());
                    }
                    return None;
                }
            }
        };
        if let Err(SearchResultError::CouldNotReadSize) = res {
            self.buffer.clear();
        }
        if let Ok(SearchResult::Done { .. }) = res
            && let Some(shutdown) = self.done.take()
        {
            let _ = shutdown.send(());
        }
        Some(res)
    }
}

pub(crate) fn read_search_as<E: FromEntry, R: Read>(
    mut bytes: R,
) -> Result<SearchResult<E>, SearchResultError> {
    let Ok(tag) = bytes.read_single_byte() else {
        return Err(SearchResultError::CouldNotReadSize);
    };
    let tag_number = tag::get_tag_number(tag);
    let msg_len = read_length(&mut bytes)?;
    let mut this_msg = vec![0; msg_len];
    let Ok(()) = bytes.read_exact(&mut this_msg) else {
        return Err(SearchResultError::InvalidSchema);
    };
    let mut bytes = this_msg.as_slice();
    match tag_number {
        4 => {
            let Ok(OCTET_STRING) = bytes.read_single_byte() else {
                return Err(SearchResultError::InvalidSchema);
            };
            let name_length = read_length(&mut bytes)?;
            let mut name_bytes = vec![0; name_length];
            let Ok(()) = bytes
                .read_exact(&mut name_bytes)
                .map_err(|_| SearchResultError::InvalidSchema)
            else {
                return Err(SearchResultError::InvalidSchema);
            };
            let Ok(object_name) = String::from_utf8(name_bytes) else {
                return Err(SearchResultError::InvalidSchema);
            };
            let Ok(UNIVERSAL_SEQUENCE) = bytes.read_single_byte() else {
                return Err(SearchResultError::InvalidSchema);
            };
            let attr_list_len = bytes
                .read_ber_length()
                .map_err(|_| SearchResultError::InvalidSchema)?;
            assert_eq!(bytes.len(), attr_list_len);
            let mut attributes = Vec::<Attribute>::new();
            while !bytes.is_empty() {
                let Ok(UNIVERSAL_SEQUENCE) = bytes.read_single_byte() else {
                    return Err(SearchResultError::InvalidSchema);
                };
                let attr_seq_len = bytes
                    .read_ber_length()
                    .map_err(|_| SearchResultError::InvalidSchema)?;
                let Some((mut attr_reader, rest)) = bytes.split_at_checked(attr_seq_len) else {
                    return Err(SearchResultError::InvalidSchema);
                };
                bytes = rest;

                let Ok(OCTET_STRING) = attr_reader.read_single_byte() else {
                    return Err(SearchResultError::InvalidSchema);
                };
                let strlen = attr_reader
                    .read_ber_length()
                    .map_err(|_| SearchResultError::InvalidSchema)?;
                let mut attr_type = String::new();
                attr_reader
                    .by_ref()
                    .take(strlen as u64)
                    .read_to_string(&mut attr_type)
                    .map_err(SearchResultError::Io)?;

                let mut attr_values = Vec::new();
                let Ok(UNIVERSAL_SET) = attr_reader.read_single_byte() else {
                    return Err(SearchResultError::InvalidSchema);
                };
                let _setlen = attr_reader
                    .read_ber_length()
                    .map_err(|_| SearchResultError::InvalidSchema)?;
                while !attr_reader.is_empty() {
                    let Ok(OCTET_STRING) = attr_reader.read_single_byte() else {
                        return Err(SearchResultError::InvalidSchema);
                    };
                    let attr_value_len = attr_reader
                        .read_ber_length()
                        .map_err(|_| SearchResultError::InvalidSchema)?;
                    let mut buf = vec![0; attr_value_len];
                    attr_reader.read_exact(&mut buf).map_err(SearchResultError::Io)?;
                    attr_values.push(buf);
                }
                attributes.push(Attribute {
                    r#type: attr_type,
                    values: attr_values,
                });
            }
            let raw_enty = RawEntry {
                object_name,
                attributes,
            };
            E::from_entry(raw_enty)
                .map_err(SearchResultError::InvalidEntry)
                .map(SearchResult::Entry)
        }
        5 => {
            let (tag, int) = bytes.read_as_tag_integer().unwrap();
            if tag != UNIVERSAL_ENUMERATED {
                return Err(SearchResultError::InvalidSchema);
            }
            let code = int
                .try_into()
                .ok()
                .and_then(ResultCode::from_code)
                .ok_or(SearchResultError::InvalidSchema)?;
            // matched dn
            if bytes
                .read_single_byte()
                .map_err(|_| SearchResultError::InvalidSchema)?
                != OCTET_STRING
            {
                return Err(SearchResultError::InvalidSchema);
            }
            let mdn_len = read_length(&mut bytes)?;
            let mut matched_dn = vec![0; mdn_len];
            bytes
                .read_exact(&mut matched_dn)
                .map_err(|_| SearchResultError::InvalidSchema)?;
            let Ok(matched_dn) = String::from_utf8(matched_dn) else {
                return Err(SearchResultError::InvalidSchema);
            };

            if bytes
                .read_single_byte()
                .map_err(|_| SearchResultError::InvalidSchema)?
                != OCTET_STRING
            {
                return Err(SearchResultError::InvalidSchema);
            }
            let dm_len = read_length(&mut bytes)?;
            let mut diagnostics_message = vec![0; dm_len];
            bytes
                .read_exact(&mut diagnostics_message)
                .map_err(|_| SearchResultError::InvalidSchema)?;
            let Ok(diagnostics_message) = String::from_utf8(diagnostics_message) else {
                return Err(SearchResultError::InvalidSchema);
            };

            Ok(SearchResult::Done {
                code,
                matched_dn,
                diagnostics_message,
            })
        }
        19 => Ok(SearchResult::Reference),
        _ => todo!(),
    }
}
#[derive(Debug)]
pub enum SearchResultError {
    CouldNotReadSize,
    Io(std::io::Error),
    InvalidEntry(FailedToGetFromEntry),
    InvalidSchema,
}
impl From<LengthError> for SearchResultError {
    fn from(value: LengthError) -> Self {
        match value {
            LengthError::Io(error) => Self::Io(error),
            LengthError::Unbounded | LengthError::OutOfRange => Self::InvalidSchema,
        }
    }
}
impl std::error::Error for SearchResultError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::InvalidSchema | Self::CouldNotReadSize => None,
            Self::Io(io) => Some(io),
            Self::InvalidEntry(ie) => Some(ie),
        }
    }
}
impl Display for SearchResultError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidEntry(i) => write!(f, "Entry did not match struct: {i}"),
            Self::CouldNotReadSize => write!(f, "failed to read message size"),
            Self::InvalidSchema => write!(f, "Invalid LDAP message"),
            Self::Io(io) => write!(f, "failed to read LDAP message: {io}"),
        }
    }
}

#[derive(Debug)]
pub enum SearchResult<T = RawEntry> {
    Entry(T),
    Reference,
    Done {
        code: ResultCode,
        matched_dn: String,
        diagnostics_message: String,
    },
}

pub(crate) fn write_search<'a>(
    base_object: &str,
    scope: Scope,
    deref_policy: DerefPolicy,
    filter: &Filter<'_>,
    attributes: impl IntoIterator<Item = &'a str>,
) -> Vec<u8> {
    let mut out = Vec::new();
    out.push(OCTET_STRING);
    out.write_ber_length(base_object.len()).unwrap();
    out.extend_from_slice(base_object.as_bytes());

    // scope
    write_integer_with_tag(&mut out, UNIVERSAL_ENUMERATED, scope.as_num().into());

    // deref Aliases
    write_integer_with_tag(&mut out, UNIVERSAL_ENUMERATED, deref_policy.as_num().into());

    // size limit
    write_integer_with_tag(&mut out, UNIVERSAL_INTEGER, 0);

    // time limit
    write_integer_with_tag(&mut out, UNIVERSAL_INTEGER, 0);

    // types only
    out.push(UNIVERSAL_BOOLEAN);
    out.write_ber_length(1).unwrap();
    out.push(0x00);

    filter.write_into(&mut out).unwrap();

    out.push(UNIVERSAL_SEQUENCE);
    let mut attr_sequence = Vec::new();
    for attr in attributes {
        attr_sequence.push(OCTET_STRING);
        attr_sequence.write_ber_length(attr.len()).unwrap();
        attr_sequence.extend_from_slice(attr.as_bytes());
    }
    out.write_ber_length(attr_sequence.len()).unwrap();
    out.extend_from_slice(&attr_sequence);

    out
}

fn write_integer_with_tag(base: &mut Vec<u8>, tag: u8, int: i32) {
    base.push(tag);
    let mut int_bytes = Vec::new();
    int_bytes.write_ber_integer_body(int).unwrap();
    base.write_ber_length(int_bytes.len()).unwrap();
    base.extend(int_bytes);
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

pub trait FromEntry: Sized {
    fn from_entry(entry: RawEntry) -> Result<Self, FailedToGetFromEntry>;

    #[must_use]
    fn attributes() -> Option<impl Iterator<Item = &'static str>> {
        None::<std::iter::Empty<&str>>
    }
}
#[derive(Debug)]
pub enum FailedToGetFromEntry {
    MissingField(&'static str),
    TooManyValues(&'static str),
    FailedToParseField(&'static str, Box<dyn Error + 'static + Send>),
}
impl Error for FailedToGetFromEntry {}
impl Display for FailedToGetFromEntry {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::MissingField(field) => write!(f, "Server did not send attribute \"{field}\""),
            Self::FailedToParseField(field, error) => {
                write!(f, "Failed to parse attribute \"{field}\": {error}")
            }
            Self::TooManyValues(field) => write!(f, "more than one value in attribute \"{field}\""),
        }
    }
}

#[cfg(feature = "from_octets")]
/// Octet string parsing logic for single value
///
/// This is the default trait to implement to work for the derive(Entry) macro.
/// If multiple values are present in a directory attribute, the deserialization will fail
pub trait FromOctetString: Sized {
    type Err: Error;
    fn from_octet_string(bytes: &[u8]) -> Result<Self, Self::Err>;
}

#[cfg(feature = "from_octets")]
/// Grabs multiple values from the reference attribute.
///
/// If any parse in the attributes fails, it will error out. To get partial parses, wrap the inner type into a type with infallible
/// octet string deserialization
pub trait FromMultipleOctetStrings: Sized {
    type Err: Error;
    fn from_multiple_octet_strings<'a>(values: impl Iterator<Item = &'a [u8]>) -> Result<Self, Self::Err>;
}
