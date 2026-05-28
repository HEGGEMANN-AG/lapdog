pub mod controls {
    use crate::{
        WriteExt,
        active_directory::oids::LDAP_PAGED_RESULT_OID_STRING,
        controls::Control,
        tag::{OCTET_STRING, UNIVERSAL_INTEGER, UNIVERSAL_SEQUENCE},
    };

    pub fn paged_result_oid_string(criticality: bool, size: i32) -> Control<'static> {
        let mut control_value = Vec::new();
        control_value
            .write_sequence(UNIVERSAL_SEQUENCE, |b| {
                let mut int_b = Vec::new();
                int_b.write_ber_integer_body(size).expect("infallible");
                b.push(UNIVERSAL_INTEGER);
                b.write_ber_length(int_b.len()).expect("infallible");
                b.extend_from_slice(&int_b);
                b.push(OCTET_STRING);
                b.write_ber_length(0).expect("infallible");
                Ok(())
            })
            .unwrap();
        let control_value = Some(control_value);
        Control {
            oid: LDAP_PAGED_RESULT_OID_STRING,
            criticality,
            control_value,
        }
    }
}

pub mod oids {
    use crate::oid::OidRef;

    pub const LDAP_PAGED_RESULT_OID_STRING: OidRef =
        OidRef::new(&[1, 2, 840, 113556, 1, 4, 319]).expect("not empty");
}
