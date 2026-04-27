use std::{
    io::{Read, Write},
    num::NonZero,
};

use crate::{
    WriteExt, attribute,
    auth::Authentication,
    bind::{self, BindStatus},
    compare::{self, ReadCompareError},
    length::{LengthError, read_length},
    modify::{self, Change, ReadModifyError},
    read::ReadExt,
    result::ResultCode,
    search::{self, DerefPolicy, Filter, Scope},
    tag::{
        PrimitiveOrConstructed as PrimOrCons, TagClass, UNIVERSAL_INTEGER, UNIVERSAL_SEQUENCE, get_tag_number,
    },
};

pub type RequestMessage<'a> = Message<RequestProtocolOp<'a>>;

#[derive(Debug)]
pub struct Message<ProtocolOp> {
    pub(crate) message_id: Option<NonZero<i32>>,
    pub(crate) protocol_op: ProtocolOp,
}
impl RequestMessage<'_> {
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut buffer = Vec::new();
        buffer.push(UNIVERSAL_SEQUENCE);

        let mut ldap_message = Vec::new();

        // Message ID
        ldap_message.push(UNIVERSAL_INTEGER);

        let id = self.message_id.map(Into::into).unwrap_or_default();
        let mut int_b = Vec::new();
        int_b.write_ber_integer_body(id).expect("infallible");

        ldap_message.write_ber_length(int_b.len()).expect("infallible");
        ldap_message.extend_from_slice(&int_b);

        // Protocol Op
        self.protocol_op
            .write_into(&mut ldap_message)
            .expect("infallible");

        buffer.write_ber_length(ldap_message.len()).expect("infallible");
        buffer.extend(&ldap_message);
        buffer
    }
}

#[derive(Clone, Debug)]
#[allow(dead_code)]
pub enum ResponseProtocolOp {
    Bind {
        status: BindStatus,
        server_sasl_creds: Option<Vec<u8>>,
    },
    SearchResultEntry,
    SearchResultDone,
    SearchResultReference,
    Modify,
    Add,
    Delete,
    ModifyDN,
    Compare {
        compare: bool,
    },
    Extended,
    Intermediate,
}
impl ProtocolOp for ResponseProtocolOp {
    fn to_tag(&self) -> u8 {
        match self {
            Self::Bind { .. } => 1,
            Self::SearchResultEntry => 4,
            Self::SearchResultDone => 5,
            Self::Modify => 7,
            Self::Add => 9,
            Self::Delete => 11,
            Self::ModifyDN => 13,
            Self::Compare { .. } => 15,
            Self::SearchResultReference => 19,
            Self::Extended => 24,
            Self::Intermediate => 25,
        }
    }
    fn read_from<R: Read>(mut r: R) -> Result<Self, ReadProtocolOpError> {
        let choice_tag = r.read_single_byte().map_err(ReadProtocolOpError::Io)?;
        let class = TagClass::from_bits(choice_tag);
        let poc = PrimOrCons::from_bit(choice_tag);
        let TagClass::Application = class else {
            panic!("Bad choice tag class")
        };
        let PrimOrCons::Constructed = poc else {
            panic!("Bad choice primitive/constructed");
        };
        let tag = get_tag_number(choice_tag);
        let len = read_length(&mut r)?;
        let message_body_reader = r.take(len as u64);
        match tag {
            1 => {
                let bind::BindResponse {
                    sasl_creds,
                    bind_status: status,
                    ..
                } = bind::read_response(message_body_reader)?;
                Ok(Self::Bind {
                    server_sasl_creds: sasl_creds,
                    status,
                })
            }
            7 => {
                modify::read_response(message_body_reader)?;
                Ok(Self::Modify)
            }
            15 => {
                let compare = compare::read_response(message_body_reader)?;
                Ok(Self::Compare { compare })
            }
            _ => todo!(),
        }
    }
}
#[derive(Debug)]
pub enum ReadProtocolOpError {
    Io(std::io::Error),
    ServerError { code: ResultCode, message: String },
    InvalidSchema,
}
impl From<bind::ReadBindError> for ReadProtocolOpError {
    fn from(e: bind::ReadBindError) -> Self {
        match e {
            bind::ReadBindError::Io(e) => Self::Io(e),
            bind::ReadBindError::InvalidResultCode | bind::ReadBindError::InvalidSchema => {
                Self::InvalidSchema
            }
            bind::ReadBindError::BindError { code, message } => Self::ServerError { code, message },
        }
    }
}
impl From<ReadCompareError> for ReadProtocolOpError {
    fn from(value: ReadCompareError) -> Self {
        match value {
            ReadCompareError::Io(error) => Self::Io(error),
            ReadCompareError::InvalidSchema => Self::InvalidSchema,
            ReadCompareError::ServerError { code, message } => Self::ServerError { code, message },
        }
    }
}
impl From<ReadModifyError> for ReadProtocolOpError {
    fn from(value: ReadModifyError) -> Self {
        match value {
            ReadModifyError::InvalidSchema => Self::InvalidSchema,
            ReadModifyError::Io(error) => Self::Io(error),
            ReadModifyError::ServerError { code, message } => Self::ServerError { code, message },
        }
    }
}
impl From<LengthError> for ReadProtocolOpError {
    fn from(value: LengthError) -> Self {
        match value {
            LengthError::Io(error) => Self::Io(error),
            LengthError::Unbounded | LengthError::OutOfRange => Self::InvalidSchema,
        }
    }
}

#[derive(Clone, Debug)]
#[allow(dead_code)]
pub enum RequestProtocolOp<'a> {
    /// Bind-dn usually empty for SASL bind
    Bind {
        authentication: Authentication<'a>,
    },
    Unbind,
    Search {
        entry: &'a str,
        scope: Scope,
        deref_policy: DerefPolicy,
        filter: Filter<'a>,
        attributes: &'a [&'a str],
    },
    Modify {
        object: &'a str,
        changes: &'a [Change<'a>],
    },
    Add,
    Delete,
    ModifyDN,
    Compare {
        entry: &'a str,
        value_assertion: attribute::AttributeValueAssertion<'a>,
    },
    Abandon,
    Extended,
}
impl ProtocolOp for RequestProtocolOp<'_> {
    fn to_tag(&self) -> u8 {
        match self {
            Self::Bind { .. } => 0,
            Self::Unbind => 2,
            Self::Search { .. } => 3,
            Self::Modify { .. } => 6,
            Self::Add => 8,
            Self::Delete => 10,
            Self::ModifyDN => 12,
            Self::Compare { .. } => 14,
            Self::Abandon => 16,
            Self::Extended => 23,
        }
    }
    fn read_from<R: Read>(_r: R) -> Result<Self, ReadProtocolOpError> {
        unimplemented!()
    }
}
impl RequestProtocolOp<'_> {
    fn write_into<W: Write>(&self, mut w: W) -> std::io::Result<()> {
        // Sequence tag
        let req_tag = TagClass::Application.into_bits() | PrimOrCons::Constructed.into_bit() | self.to_tag();
        w.write_single_byte(req_tag)?;
        let proto_op_inner = match self {
            Self::Bind { authentication } => bind::write_bind(authentication),
            Self::Compare {
                entry,
                value_assertion,
            } => compare::write_compare(entry, value_assertion),
            Self::Search {
                entry: base_object,
                scope,
                deref_policy,
                filter,
                attributes,
            } => search::write_search(
                base_object,
                *scope,
                *deref_policy,
                filter,
                attributes.iter().copied(),
            ),
            Self::Modify { object, changes } => modify::write_modify(object, changes),
            _ => todo!(),
        };
        w.write_ber_length(proto_op_inner.len())?;
        w.write_all(&proto_op_inner)?;
        Ok(())
    }
}

pub trait ProtocolOp: Sized {
    fn to_tag(&self) -> u8;
    fn read_from<R: Read>(r: R) -> Result<Self, ReadProtocolOpError>;
}
