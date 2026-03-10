use std::borrow::Cow;

#[derive(Clone, Debug)]
pub enum Authentication<'a> {
    Sasl {
        mechanism: SaslMechanism,
        credentials: Option<Cow<'a, [u8]>>,
    },
}
impl Authentication<'_> {
    pub fn sasl_gss<'t>(token: Option<&'t [u8]>) -> Authentication<'t> {
        Authentication::Sasl {
            mechanism: SaslMechanism::GssAPI,
            credentials: token.map(Cow::Borrowed),
        }
    }
}

#[derive(Clone, Copy, Debug)]
pub enum SaslMechanism {
    GssAPI,
}
