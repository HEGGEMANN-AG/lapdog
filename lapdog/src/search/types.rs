use std::io::Write;

use crate::{
    WriteExt,
    attribute::AttributeValueAssertion,
    tag::{PrimitiveOrConstructed, TagClass},
};

#[derive(Clone, Copy, Debug)]
pub enum Scope {
    Base = 0,
    SingleLevel = 1,
    WholeSubtree = 2,
}
impl Scope {
    pub fn as_num(self) -> u8 {
        self as u8
    }
}

#[derive(Clone, Copy, Debug)]
pub enum DerefPolicy {
    Never = 0,
    InSearching = 1,
    FindingBaseObj = 2,
    Always = 3,
}
impl DerefPolicy {
    pub fn as_num(self) -> u8 {
        self as u8
    }
}

#[derive(Copy, Clone, Debug)]
pub enum Filter<'a> {
    And(&'a [&'a Filter<'a>]),
    Or(&'a [&'a Filter<'a>]),
    Not(&'a Filter<'a>),
    Equal(AttributeValueAssertion<'a>),
    // substring
    GreaterOrEqual(AttributeValueAssertion<'a>),
    LessOrEqual(AttributeValueAssertion<'a>),
    Present(&'a str),
    ApproxMatch(AttributeValueAssertion<'a>),
}
impl Filter<'_> {
    fn tag_number(&self) -> u8 {
        match self {
            Filter::And(_) => 0,
            Filter::Or(_) => 1,
            Filter::Not(_) => 2,
            Filter::Equal(_) => 3,
            Filter::GreaterOrEqual(_) => 5,
            Filter::LessOrEqual(_) => 6,
            Filter::Present(_) => 7,
            Filter::ApproxMatch(_) => 8,
        }
    }
    fn primitive_or_constructed(&self) -> PrimitiveOrConstructed {
        match self {
            Filter::Present(_) => PrimitiveOrConstructed::Primitive,
            _ => PrimitiveOrConstructed::Constructed,
        }
    }
    pub(super) fn write_into<W: Write>(&self, mut w: W) -> Result<(), std::io::Error> {
        let tag = TagClass::ContextSpecific.into_bits()
            | self.primitive_or_constructed().into_bit()
            | self.tag_number();
        w.write_single_byte(tag)?;

        let mut v = Vec::new();
        match self {
            Self::And(f) | Self::Or(f) => {
                for subfilter in f.iter() {
                    subfilter.write_into(&mut v)?;
                }
            }
            Self::Not(f) => {
                f.write_into(&mut v)?;
            }
            Self::Present(attr) => {
                v.extend_from_slice(attr.as_bytes());
            }
            Filter::Equal(ava)
            | Filter::GreaterOrEqual(ava)
            | Filter::LessOrEqual(ava)
            | Filter::ApproxMatch(ava) => ava.write_into(&mut v)?,
        };
        w.write_ber_length(v.len())?;
        w.write_all(&v)?;
        Ok(())
    }
}
