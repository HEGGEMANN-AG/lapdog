use std::{
    fmt::Display,
    io::{Read, Write},
    num::NonZero,
};

use tokio::io::AsyncWriteExt;

use crate::{
    WriteExt,
    auth::Authentication,
    bind::{self, BindStatus},
    integer::{INTEGER_BYTE, read_integer_body},
    length::{read_length, write_length},
    read::ReadExt,
    tag::{
        PrimitiveOrConstructed as PrimOrCons, TagClass, UNIVERSAL_SEQUENCE, get_tag_number, is_tag_triple,
    },
};

pub type RequestMessage<'a> = Message<RequestProtocolOp<'a>>;
pub type ResponseMessage = Message<ResponseProtocolOp>;

#[derive(Debug)]
pub struct Message<ProtocolOp> {
    pub(crate) message_id: Option<NonZero<i32>>,
    pub(crate) protocol_op: ProtocolOp,
}
impl<PO: ProtocolOp> Message<PO> {
    pub fn read_from<R: Read>(mut r: R) -> Result<Self, Error> {
        let seq_tag = r.read_single_byte()?;
        if !is_tag_triple(seq_tag, TagClass::Universal, PrimOrCons::Constructed, 0b00010000) {
            return Err(Error::InvalidMessageStructure);
        }
        let Ok(Some(seq_length)) = read_length(&mut r) else {
            return Err(Error::InvalidMessageStructure);
        };

        let mut buffer = vec![0; seq_length];
        r.read_exact(&mut buffer).map_err(|_| Error::UnexpectedEOF)?;
        let mut buf_reader = buffer.as_slice();
        let int_tag = buf_reader.read_single_byte().map_err(|_| Error::UnexpectedEOF)?;
        if !is_tag_triple(int_tag, TagClass::Universal, PrimOrCons::Primitive, 0x02) {
            return Err(Error::InvalidMessageStructure);
        }
        let Ok(Some(integer_length)) = read_length(&mut buf_reader) else {
            return Err(Error::InvalidMessageId);
        };
        let (int, buf_reader) = buf_reader.split_at(integer_length);

        let message_id = NonZero::new(read_integer_body(int).map_err(|_| Error::InvalidMessageId)?);

        let protocol_op = PO::read_from(buf_reader)?;
        Ok(Message {
            message_id,
            protocol_op,
        })
    }
    pub fn to_bytes(&self) -> std::io::Result<Vec<u8>> {
        let mut buffer = Vec::new();
        buffer.write_single_byte(UNIVERSAL_SEQUENCE)?;

        let mut ldap_message = Vec::new();

        // Message ID
        ldap_message.write_single_byte(INTEGER_BYTE)?;

        let id = self.message_id.map(Into::into).unwrap_or_default();
        let mut int_b = Vec::new();
        int_b.write_ber_integer(id)?;

        write_length(&mut ldap_message, int_b.len())?;
        Write::write_all(&mut ldap_message, &int_b)?;

        // Protocol Op
        self.protocol_op.write_into(&mut ldap_message)?;

        write_length(&mut buffer, ldap_message.len())?;
        Write::write_all(&mut buffer, &ldap_message)?;
        Ok(buffer)
    }
    pub fn write_to<W: Write>(&self, mut w: W) -> std::io::Result<()> {
        Write::write_all(&mut w, &self.to_bytes()?)?;
        Ok(())
    }
    pub async fn write_to_async<W: AsyncWriteExt + Unpin>(&self, w: &mut W) -> std::io::Result<()> {
        w.write_all(&self.to_bytes()?).await?;
        Ok(())
    }
}

#[derive(Clone, Debug)]
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
    Compare,
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
            Self::Compare => 15,
            Self::SearchResultReference => 19,
            Self::Extended => 24,
            Self::Intermediate => 25,
        }
    }
    fn write_into<W: Write>(&self, mut w: W) -> std::io::Result<()> {
        w.write_single_byte(
            TagClass::Application.into_bits() | PrimOrCons::Primitive.into_bit() | self.to_tag(),
        )?;
        todo!()
    }
    fn read_from<R: Read>(mut r: R) -> std::io::Result<Self> {
        let choice_tag = r.read_single_byte()?;
        let class = TagClass::from_bits(choice_tag);
        let poc = PrimOrCons::from_bit(choice_tag);
        let TagClass::Application = class else {
            panic!("Bad choice tag class")
        };
        let PrimOrCons::Constructed = poc else {
            panic!("Bad choice primitive/constructed");
        };
        let tag = get_tag_number(choice_tag);
        let len = read_length(&mut r)?.unwrap();
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
            _ => todo!(),
        }
    }
}

#[derive(Clone, Debug)]
pub enum RequestProtocolOp<'a> {
    /// Bind-dn usually empty for SASL bind
    Bind {
        authentication: Authentication<'a>,
    },
    Unbind,
    Search,
    Modify,
    Add,
    Delete,
    ModifyDN,
    Compare,
    Abandon,
    Extended,
}
impl ProtocolOp for RequestProtocolOp<'_> {
    fn to_tag(&self) -> u8 {
        match self {
            Self::Bind { .. } => 0,
            Self::Unbind => 2,
            Self::Search => 3,
            Self::Modify => 6,
            Self::Add => 8,
            Self::Delete => 10,
            Self::ModifyDN => 12,
            Self::Compare => 14,
            Self::Abandon => 16,
            Self::Extended => 23,
        }
    }
    fn read_from<R: Read>(_r: R) -> std::io::Result<Self> {
        unimplemented!()
    }
    fn write_into<W: Write>(&self, mut w: W) -> std::io::Result<()> {
        let req_tag = TagClass::Application.into_bits() | PrimOrCons::Constructed.into_bit() | self.to_tag();
        w.write_single_byte(req_tag)?;
        let proto_op_inner = match self {
            Self::Bind { authentication } => bind::write_bind(authentication)?,
            _ => todo!(),
        };
        write_length(&mut w, proto_op_inner.len())?;
        w.write_all(&proto_op_inner)?;
        Ok(())
    }
}

pub trait ProtocolOp: Sized {
    fn to_tag(&self) -> u8;
    fn read_from<R: Read>(r: R) -> std::io::Result<Self>;
    fn write_into<W: Write>(&self, w: W) -> std::io::Result<()>;
}

#[derive(Debug)]
pub enum Error {
    InvalidMessageId,
    InvalidMessageStructure,
    InvalidProtocolOp,
    UnexpectedEOF,
}
impl From<std::io::Error> for Error {
    fn from(_val: std::io::Error) -> Self {
        Self::UnexpectedEOF
    }
}
impl Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidMessageId => write!(f, "Invalid message ID"),
            Self::InvalidMessageStructure => write!(f, "Invalid message structure"),
            Self::InvalidProtocolOp => write!(f, "Invalid protocol op"),
            Self::UnexpectedEOF => write!(f, "Unexpected end of stream"),
        }
    }
}
