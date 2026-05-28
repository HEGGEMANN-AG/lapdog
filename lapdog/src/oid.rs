use std::{
    fmt::{Display, Formatter, Result as FmtResult},
    iter::Copied,
    slice::Iter,
};

#[derive(Clone, Debug)]
pub struct Oid(Vec<u32>);
impl Oid {
    pub fn new(v: Vec<u32>) -> Option<Self> {
        (!v.is_empty()).then_some(Self(v))
    }
    pub fn as_ref(&self) -> OidRef<'_> {
        OidRef(&self.0)
    }
}
impl Display for Oid {
    fn fmt(&self, f: &mut Formatter<'_>) -> FmtResult {
        self.as_ref().fmt(f)
    }
}

#[derive(Clone)]
pub struct Elements<'a>(Copied<Iter<'a, u32>>);
impl Iterator for Elements<'_> {
    type Item = u32;
    fn next(&mut self) -> Option<Self::Item> {
        self.0.next()
    }
}

#[derive(Copy, Clone, Debug)]
pub struct OidRef<'i>(&'i [u32]);
impl OidRef<'_> {
    pub const fn new<'i>(v: &'i [u32]) -> Option<OidRef<'i>> {
        if v.is_empty() { None } else { Some(OidRef(v)) }
    }
    pub fn elements(&self) -> Elements<'_> {
        Elements(self.0.iter().copied())
    }
}
impl Display for OidRef<'_> {
    fn fmt(&self, f: &mut Formatter<'_>) -> FmtResult {
        for (num, value) in self.0.iter().copied().enumerate() {
            let is_last = self.0.len() == num + 1;
            write!(f, "{value}")?;
            if !is_last {
                write!(f, ".")?;
            }
        }
        Ok(())
    }
}
