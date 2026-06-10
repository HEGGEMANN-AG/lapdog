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
