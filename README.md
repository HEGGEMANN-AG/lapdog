# Lapdog

LDAP library for searching an LDAP directory with proper Rust structs as output.

Supports simple, Kerberos and (panicking) TLS external binding with both [rustls](https://crates.io/crates/rustls) and [native-tls](https://crates.io/crates/native-tls) TLS backends.

Upcoming/Planned features:
- Modify/Delete etc
- Default attribute for derive (optional handling of missing attributes).

So far, all filtering and scoping is redirected towards the dependency library [rasn-ldap](https://crates.io/crates/rasn-ldap)

Maintained by HEGGEMANN AG, a small aerospace company in Germany
