use std::{
    io::Write,
    ops::{BitAnd, BitOr, Not},
};

use crate::{
    WriteExt as _,
    attribute::AttributeValueAssertion,
    tag::{PrimitiveOrConstructed, TagClass},
};

#[derive(Clone, Debug)]
pub enum Filter<'a> {
    And(Vec<Filter<'a>>),
    Or(Vec<Filter<'a>>),
    Not(Box<Filter<'a>>),
    Equal(AttributeValueAssertion<'a>),
    // substring
    GreaterOrEqual(AttributeValueAssertion<'a>),
    LessOrEqual(AttributeValueAssertion<'a>),
    Present(&'a str),
    ApproxMatch(AttributeValueAssertion<'a>),
    ExtensibleMatch(MatchingRuleAssertion<'a>),
}
impl Filter<'_> {
    pub fn and<'f>(filters: impl IntoIterator<Item = Filter<'f>>) -> Filter<'f> {
        let filters = filters.into_iter().collect();
        Filter::And(filters)
    }
    pub fn or<'f>(filters: impl IntoIterator<Item = Filter<'f>>) -> Filter<'f> {
        let filters = filters.into_iter().collect();
        Filter::Or(filters)
    }
    pub fn equal<'s>(attribute_desc: &'s str, value: &'s [u8]) -> Filter<'s> {
        Filter::Equal(AttributeValueAssertion::new(attribute_desc, value))
    }
    pub fn greater_or_equal<'s>(attribute_desc: &'s str, value: &'s [u8]) -> Filter<'s> {
        Filter::GreaterOrEqual(AttributeValueAssertion::new(attribute_desc, value))
    }
    pub fn less_or_equal<'s>(attribute_desc: &'s str, value: &'s [u8]) -> Filter<'s> {
        Filter::LessOrEqual(AttributeValueAssertion::new(attribute_desc, value))
    }
    pub fn approximate_match<'s>(attribute_desc: &'s str, value: &'s [u8]) -> Filter<'s> {
        Filter::ApproxMatch(AttributeValueAssertion::new(attribute_desc, value))
    }
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
            Filter::ExtensibleMatch(_) => 9,
        }
    }
    fn primitive_or_constructed(&self) -> PrimitiveOrConstructed {
        match self {
            Filter::Present(_) => PrimitiveOrConstructed::Primitive,
            _ => PrimitiveOrConstructed::Constructed,
        }
    }
    fn tag(&self) -> u8 {
        TagClass::ContextSpecific.into_bits() | self.primitive_or_constructed().into_bit() | self.tag_number()
    }
    pub(super) fn write_into<W: Write>(&self, mut wout: W) -> Result<(), std::io::Error> {
        let tag = self.tag();

        wout.write_sequence(tag, |mut v| {
            match self {
                Self::And(f) | Self::Or(f) => {
                    for subfilter in f {
                        subfilter.write_into(&mut v)?;
                    }
                }
                Self::Not(f) => {
                    f.write_into(v)?;
                }
                Self::Present(attr) => {
                    v.extend_from_slice(attr.as_bytes());
                }
                Filter::Equal(ava)
                | Filter::GreaterOrEqual(ava)
                | Filter::LessOrEqual(ava)
                | Filter::ApproxMatch(ava) => ava.write_body_into(v)?,
                Filter::ExtensibleMatch(em) => em.write_body_into(v),
            };
            Ok(())
        })?;

        Ok(())
    }
}
impl BitAnd for Filter<'_> {
    type Output = Self;

    fn bitand(self, rhs: Self) -> Self::Output {
        match (self, rhs) {
            (Filter::And(mut filters), Filter::And(more_filters)) => {
                filters.extend(more_filters);
                Self::And(filters)
            }
            (Filter::And(mut filters), other) => {
                filters.push(other);
                Self::And(filters)
            }
            (not_and, Filter::And(others)) => {
                let mut filters = Vec::with_capacity(others.len().saturating_add(1));
                filters.push(not_and);
                filters.extend_from_slice(&others);
                Self::And(filters)
            }
            (not_and, rhs) => Self::And(vec![not_and, rhs]),
        }
    }
}
impl BitOr for Filter<'_> {
    type Output = Self;

    fn bitor(self, rhs: Self) -> Self::Output {
        match (self, rhs) {
            (Filter::Or(mut filters), Filter::Or(more_filters)) => {
                filters.extend(more_filters);
                Self::Or(filters)
            }
            (Filter::Or(mut filters), other) => {
                filters.push(other);
                Self::Or(filters)
            }
            (not_and, Filter::Or(others)) => {
                let mut filters = Vec::with_capacity(others.len().saturating_add(1));
                filters.push(not_and);
                filters.extend_from_slice(&others);
                Self::Or(filters)
            }
            (not_and, rhs) => Self::Or(vec![not_and, rhs]),
        }
    }
}
impl Not for Filter<'_> {
    type Output = Self;
    fn not(self) -> Self::Output {
        Self::Not(Box::new(self))
    }
}

#[derive(Debug, Clone)]
pub struct MatchingRuleAssertion<'a> {
    pub matching_rule: Option<&'a str>,
    pub r#type: Option<&'a str>,
    pub match_value: &'a [u8],
    pub dn_attributes: Option<bool>,
}

const MATCHING_RULE: u8 =
    TagClass::ContextSpecific.into_bits() | PrimitiveOrConstructed::Primitive.into_bit() | 0x1;
const ATTR_DESC_TYPE: u8 =
    TagClass::ContextSpecific.into_bits() | PrimitiveOrConstructed::Primitive.into_bit() | 0x2;
const MATCH_VALUE: u8 =
    TagClass::ContextSpecific.into_bits() | PrimitiveOrConstructed::Primitive.into_bit() | 0x3;
const DN_ATTRIBUTES: u8 =
    TagClass::ContextSpecific.into_bits() | PrimitiveOrConstructed::Primitive.into_bit() | 0x4;

impl MatchingRuleAssertion<'_> {
    fn write_body_into(&self, w: &mut Vec<u8>) {
        if let Some(mr) = self.matching_rule {
            w.push(MATCHING_RULE);
            w.write_ber_length(mr.len()).unwrap();
            w.extend_from_slice(mr.as_bytes());
        }
        if let Some(t) = self.r#type {
            w.push(ATTR_DESC_TYPE);
            w.write_ber_length(t.len()).unwrap();
            w.extend_from_slice(t.as_bytes());
        }
        w.push(MATCH_VALUE);
        w.write_ber_length(self.match_value.len()).unwrap();
        w.extend_from_slice(self.match_value);
        if let Some(b) = self.dn_attributes {
            w.push(DN_ATTRIBUTES);
            w.write_ber_length(1).unwrap();
            w.push(if b { 0xFF } else { 0x00 });
        }
    }
}
