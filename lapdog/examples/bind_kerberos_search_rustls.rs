use std::sync::Arc;

use kenobi::{cred::Credentials, mech::Mechanism};

use lapdog::{
    LDAPS_PORT, LdapConnection, StreamConfig,
    search::{DerefPolicy, Filter, Scope, SearchResult},
};
use lapdog_derive::Entry;
use rustls::{
    KeyLogFile, RootCertStore,
    pki_types::{CertificateDer, pem::PemObject},
};

#[tokio::main]
async fn main() {
    let server = std::env::var("LAPDOG_SERVER").unwrap();
    let target_spn = std::env::var("LAPDOG_TARGET_SPN").ok();
    let own_spn = std::env::var("LAPDOG_OWN_SPN").ok();
    let cred = Credentials::outbound(own_spn.as_deref(), Mechanism::KerberosV5).unwrap();
    let mut roots = RootCertStore::empty();
    let der = CertificateDer::from_pem_file(std::env::var("LAPDOG_ROOT_CERT").unwrap()).unwrap();
    roots.add(der).unwrap();
    let config = Arc::new({
        let mut c = rustls::ClientConfig::builder()
            .with_root_certificates(Arc::new(roots))
            .with_no_client_auth();
        c.key_log = Arc::new(KeyLogFile::new());
        c
    });
    let domain = server.clone();
    let conf = StreamConfig::Rustls { config, domain };
    let mut connection = LdapConnection::new(&(server, LDAPS_PORT), &conf).await.unwrap();
    connection
        .bind_sasl_kenobi(cred.clone(), target_spn.as_deref())
        .await
        .unwrap();
    search_users(&mut connection).await
}

#[derive(Debug, Entry)]
struct User {
    #[lapdog(rename = "userPrincipalName")]
    upn: String,
    #[lapdog(rename = "memberOf", default, multiple)]
    #[allow(dead_code)]
    member_of: Vec<String>,
}

async fn search_users(ldap: &mut LdapConnection) {
    let filter = Filter::Present("userPrincipalName");
    let search_base = std::env::var("LAPDOG_TEST_SEARCH_BASE").unwrap();
    let control = lapdog::active_directory::controls::paged_result_oid_string(true, 3);
    let mut search = ldap
        .search_with_controls_as::<User>(
            &search_base,
            Scope::WholeSubtree,
            DerefPolicy::InSearching,
            filter,
            &[control],
        )
        .await
        .unwrap();
    let mut count = 0;
    loop {
        use std::time::Duration;

        match tokio::time::timeout(Duration::from_secs(4), search.next()).await {
            Ok(Some(Ok(SearchResult::Entry(User { upn, .. })))) => {
                println!("Found user {upn}");
                count += 1
            }
            Ok(Some(Err(e))) => println!("Encountered search error: {e:?}"),
            Ok(Some(Ok(SearchResult::Reference))) => {}
            Ok(Some(Ok(SearchResult::Done { .. }))) | Ok(None) | Err(_) => break,
        };
    }
    println!("Server sent {count} entries")
}
