use std::borrow::Cow;

#[derive(Clone, Debug)]
pub enum Authentication<'a> {
    Sasl {
        mechanism: SaslMechanism,
        credentials: Option<Cow<'a, [u8]>>,
    },
}
impl Authentication<'_> {
    pub fn sasl_kerberos<'t>(token: Option<&'t [u8]>) -> Authentication<'t> {
        Authentication::Sasl {
            mechanism: SaslMechanism::GSSAPI,
            credentials: token.map(Cow::Borrowed),
        }
    }
    pub fn sasl_negotiate<'t>(token: Option<&'t [u8]>) -> Authentication<'t> {
        Authentication::Sasl {
            mechanism: SaslMechanism::GSSSPNEGO,
            credentials: token.map(Cow::Borrowed),
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[allow(clippy::upper_case_acronyms)]
pub enum SaslMechanism {
    GSSAPI,
    GSSSPNEGO,
}
