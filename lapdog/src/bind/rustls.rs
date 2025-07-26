use std::io::{Read, Write};

use rustls::{ClientConnection, StreamOwned};

use crate::{LdapConnection, bind::SaslExternalBindError};

unsafe impl<T: Read + Write> super::Safe for rustls::StreamOwned<ClientConnection, T> {}
super::impl_bound!(BoundRustls);

impl<Stream: Read + Write, BindState> LdapConnection<StreamOwned<ClientConnection, Stream>, BindState> {
    pub fn sasl_external_bind(
        self,
        auth_z_id: &str,
    ) -> Result<LdapConnection<StreamOwned<ClientConnection, Stream>, BoundRustls>, SaslExternalBindError> {
        self.internal_sasl_external_bind(auth_z_id, BoundRustls::new)
    }
}
