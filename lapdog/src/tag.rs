pub const UNIVERSAL_SEQUENCE: u8 =
    TagClass::Universal.into_bits() | PrimitiveOrConstructed::Constructed.into_bit() | 0x10;
pub const UNIVERSAL_ENUMERATED: u8 =
    TagClass::Universal.into_bits() | PrimitiveOrConstructed::Primitive.into_bit() | 0x0a;
pub const OCTET_STRING: u8 =
    TagClass::Universal.into_bits() | PrimitiveOrConstructed::Primitive.into_bit() | 0x04;

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum TagClass {
    Universal,
    Application,
    ContextSpecific,
    Private,
}
impl TagClass {
    pub const fn into_bits(self) -> u8 {
        match self {
            Self::Universal => 0x00,
            Self::Application => 0x40,
            Self::ContextSpecific => 0x80,
            Self::Private => 0xC0,
        }
    }
    pub fn from_bits(b: u8) -> Self {
        match b & 0xC0 {
            0 => Self::Universal,
            0x40 => Self::Application,
            0x80 => Self::ContextSpecific,
            0xC0 => Self::Private,
            _ => unreachable!(),
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq)]
pub enum PrimitiveOrConstructed {
    Primitive,
    Constructed,
}
impl PrimitiveOrConstructed {
    pub const fn into_bit(self) -> u8 {
        match self {
            Self::Primitive => 0,
            Self::Constructed => 0x20,
        }
    }
    pub fn from_bit(b: u8) -> Self {
        if b & 0x20 == 0 {
            Self::Primitive
        } else {
            Self::Constructed
        }
    }
}

pub fn get_tag_number(b: u8) -> u8 {
    b & 0x1F
}

pub fn is_tag_triple(b: u8, class: TagClass, poc: PrimitiveOrConstructed, number: u8) -> bool {
    TagClass::from_bits(b) == class
        && PrimitiveOrConstructed::from_bit(b) == poc
        && get_tag_number(b) == number
}

#[cfg(test)]
mod test {
    use crate::tag::{PrimitiveOrConstructed, TagClass, get_tag_number};

    fn check_tag(
        input: u8,
        expected_class: TagClass,
        expected_form: PrimitiveOrConstructed,
        expected_tag_number: u8,
    ) {
        assert_eq!(TagClass::from_bits(input), expected_class);
        assert_eq!(PrimitiveOrConstructed::from_bit(input), expected_form);
        assert_eq!(get_tag_number(input), expected_tag_number);
    }
    #[test]
    fn bool() {
        check_tag(
            0x01,
            TagClass::Universal,
            PrimitiveOrConstructed::Primitive,
            0x01,
        );
    }
    #[test]
    fn integer() {
        check_tag(
            0x02,
            TagClass::Universal,
            PrimitiveOrConstructed::Primitive,
            2,
        );
    }
    #[test]
    fn octet_string() {
        check_tag(
            0x04,
            TagClass::Universal,
            PrimitiveOrConstructed::Primitive,
            4,
        );
    }
    #[test]
    fn null() {
        check_tag(
            0x05,
            TagClass::Universal,
            PrimitiveOrConstructed::Primitive,
            5,
        );
    }
}
