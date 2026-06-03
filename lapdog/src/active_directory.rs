pub mod controls {
    use crate::{
        WriteExt,
        controls::ControlRef,
        tag::{OCTET_STRING, UNIVERSAL_INTEGER, UNIVERSAL_SEQUENCE},
    };

    pub fn paged_result_oid_string(criticality: bool, size: i32) -> ControlRef<'static> {
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
            .expect("write to Vec is infallible");
        let control_value = Some(control_value);
        ControlRef {
            oid: super::oids::LDAP_PAGED_RESULT_OID_STRING,
            criticality,
            control_value,
        }
    }
    /// Remember to user Present("objectClass") as filter.
    pub fn server_notification(criticality: bool) -> ControlRef<'static> {
        ControlRef {
            oid: super::oids::LDAP_SERVER_NOTIFICATION,
            criticality,
            control_value: None,
        }
    }
}

pub mod oids {
    use crate::oid::OidRef;

    macro_rules! with_microsoft_prefix {
        ($e:expr) => {
            OidRef::new(&[1, 2, 840, 113556, 1, 4, $e]).expect("not empty")
        };
    }

    pub const LDAP_PAGED_RESULT_OID_STRING: OidRef = with_microsoft_prefix!(319);
    pub const LDAP_SERVER_NOTIFICATION: OidRef = with_microsoft_prefix!(528);
}
