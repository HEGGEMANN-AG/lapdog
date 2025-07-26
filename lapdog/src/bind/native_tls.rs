use native_tls::TlsStream;

use crate::{LdapConnection, bind::SaslExternalBindError};

unsafe impl<T> super::Safe for native_tls::TlsStream<T> {}
super::impl_bound!(BoundNativeTls);

impl<Stream: std::io::Read + std::io::Write, BindState> LdapConnection<native_tls::TlsStream<Stream>, BindState> {
    pub fn sasl_external_bind(
        self,
        auth_z_id: &str,
    ) -> Result<LdapConnection<TlsStream<Stream>, BoundNativeTls>, SaslExternalBindError> {
        self.internal_sasl_external_bind(auth_z_id, BoundNativeTls::new)
    }
}
