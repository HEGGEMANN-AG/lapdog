use kenobi::{
    client::ClientContext,
    cred::Outbound,
    typestate::{Encryption, MaybeDelegation, MaybeEncryption, MaybeSigning, Signing},
};
pub enum ValidatedContext {
    Kerberos(ClientContext<Outbound, Signing, Encryption, MaybeDelegation>),
    Tls,
}
impl ValidatedContext {
    pub fn validate(
        ctx: ClientContext<Outbound, MaybeSigning, MaybeEncryption, MaybeDelegation>,
        is_tls: bool,
    ) -> Option<Self> {
        if is_tls {
            Some(Self::Tls)
        } else {
            ctx.check_signing()
                .ok()
                .and_then(|c| c.check_encryption().ok())
                .map(Self::Kerberos)
        }
    }
}
