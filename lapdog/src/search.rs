use std::{collections::VecDeque, io::Read};

use crate::{
    LdapConnection, ReceiveMessageError, WriteExt,
    integer::read_integer_body,
    length::read_length,
    message::RequestProtocolOp,
    read::ReadExt,
    result::ResultCode,
    tag::{
        self, OCTET_STRING, UNIVERSAL_BOOLEAN, UNIVERSAL_ENUMERATED, UNIVERSAL_INTEGER, UNIVERSAL_SEQUENCE,
    },
};

mod types;
use tokio::sync::{mpsc::UnboundedReceiver, oneshot::Sender};
pub use types::{DerefPolicy, Filter, Scope};

impl LdapConnection {
    pub async fn search<'a>(
        &self,
        base_object: &str,
        scope: Scope,
        deref_policy: DerefPolicy,
        filter: Filter<'_>,
        attributes: impl IntoIterator<Item = &'a str>,
    ) -> SearchResults {
        let attributes: Vec<&str> = attributes.into_iter().collect();
        let proto = RequestProtocolOp::Search {
            base_object,
            scope,
            deref_policy,
            filter,
            attributes: &attributes,
        };
        let (incoming_messages, done) = self.send_message(proto).await.unwrap().into_receiver();
        SearchResults {
            incoming_messages,
            buffer: Default::default(),
            done: Some(done),
        }
    }
}

pub struct SearchResults {
    incoming_messages: UnboundedReceiver<Result<Vec<u8>, ReceiveMessageError>>,
    buffer: VecDeque<u8>,
    done: Option<Sender<()>>,
}
impl SearchResults {
    pub async fn next(&mut self) -> Option<Result<SearchResult, SearchResultError>> {
        let res = if !self.buffer.is_empty() {
            read_search(&mut self.buffer)
        } else {
            match self.incoming_messages.recv().await {
                Some(Ok(body)) => {
                    self.buffer = body.into();
                    read_search(&mut self.buffer)
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
        Some(res)
    }
}

pub(crate) fn read_search<R: Read>(mut bytes: R) -> Result<SearchResult, SearchResultError> {
    let Ok(tag) = bytes.read_single_byte() else {
        return Err(SearchResultError::CouldNotReadSize);
    };
    let tag_number = tag::get_tag_number(tag);
    let Ok(Some(msg_len)) = read_length(&mut bytes) else {
        return Err(SearchResultError::CouldNotReadSize);
    };
    let mut this_msg = vec![0; msg_len];
    let Ok(()) = bytes.read_exact(&mut this_msg) else {
        return Err(SearchResultError::InvalidSchema);
    };
    let mut bytes = this_msg.as_slice();
    match tag_number {
        4 => {
            let Ok(name_tag) = bytes.read_single_byte() else {
                return Err(SearchResultError::InvalidSchema);
            };
            assert_eq!(name_tag, OCTET_STRING);
            let Ok(Some(name_length)) = read_length(&mut bytes) else {
                return Err(SearchResultError::InvalidSchema);
            };
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
            Ok(SearchResult::Entry { object_name })
        }
        5 => {
            if bytes
                .read_single_byte()
                .map_err(|_| SearchResultError::InvalidSchema)?
                != UNIVERSAL_ENUMERATED
            {
                return Err(SearchResultError::InvalidSchema);
            }
            let Ok(Some(int_len)) = read_length(&mut bytes) else {
                return Err(SearchResultError::InvalidSchema);
            };
            let mut int = vec![0; int_len];
            bytes
                .read_exact(&mut int)
                .map_err(|_| SearchResultError::InvalidSchema)?;
            let code = read_integer_body(&int)
                .ok()
                .and_then(|i| i.try_into().ok())
                .and_then(ResultCode::from_code)
                .ok_or(SearchResultError::InvalidSchema)?;
            Ok(SearchResult::Done { code })
        }
        19 => Ok(SearchResult::Reference),
        _ => todo!(),
    }
}
#[derive(Debug)]
pub enum SearchResultError {
    CouldNotReadSize,
    InvalidSchema,
}

#[derive(Debug)]
pub enum SearchResult {
    Entry { object_name: String },
    Reference,
    Done { code: ResultCode },
}

pub(crate) fn write_search<'a>(
    base_object: &str,
    scope: Scope,
    deref_policy: DerefPolicy,
    filter: Filter<'_>,
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
    int_bytes.write_ber_integer(int).unwrap();
    base.write_ber_length(int_bytes.len()).unwrap();
    base.extend(int_bytes);
}
