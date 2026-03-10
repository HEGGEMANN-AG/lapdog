#[derive(Clone, Debug)]
pub enum Authentication {
    Sasl {
        mechanism: SaslMechanism,
        credentials: Option<Vec<u8>>,
    },
}

#[derive(Clone, Copy, Debug)]
pub enum SaslMechanism {
    GssAPI,
}
