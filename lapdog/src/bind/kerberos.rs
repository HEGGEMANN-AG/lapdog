use kenobi::{
    client::ClientContext,
    cred::Outbound,
    typestate::{Encryption, MaybeDelegation, MaybeEncryption, MaybeSigning, Signing},
};
pub enum ValidatedContext<'cred> {
    Kerberos(ClientContext<'cred, Outbound, Signing, Encryption, MaybeDelegation>),
    Tls(ClientContext<'cred, Outbound, MaybeSigning, MaybeEncryption, MaybeDelegation>),
}
impl<'cred> ValidatedContext<'cred> {
    pub fn validate(
        ctx: ClientContext<'cred, Outbound, MaybeSigning, MaybeEncryption, MaybeDelegation>,
        is_tls: bool,
    ) -> Option<Self> {
        if is_tls {
            Some(Self::Tls(ctx))
        } else {
            ctx.check_signing()
                .ok()
                .and_then(|c| c.check_encryption().ok())
                .map(Self::Kerberos)
        }
    }
    pub fn last_token(&self) -> Option<&[u8]> {
        match self {
            Self::Kerberos(client_context) => client_context.last_token(),
            Self::Tls(client_context) => client_context.last_token(),
        }
    }
}
