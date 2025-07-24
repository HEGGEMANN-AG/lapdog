use std::net::SocketAddr;

use lapdog::{LdapConnection, search::Entry};
use rasn_ldap::{AttributeValueAssertion, Filter, SearchRequestDerefAliases, SearchRequestScope};

fn main() {
    let ip: SocketAddr = std::env::var("LAPDOG_IP").unwrap().parse().unwrap();
    let unbound = LdapConnection::connect(ip).unwrap();
    let username = std::env::var("LAPDOG_USER").unwrap();
    let password = std::env::var("LAPDOG_PW").unwrap();
    let mut bound = unbound
        .unsafe_bind_simple_authenticated(&username, password.as_bytes())
        .unwrap();
    let search_filter = Filter::Not(Box::new(Filter::EqualityMatch(AttributeValueAssertion::new(
        "givenName".into(),
        b"Steve".to_vec().into(),
    ))));
    let search_results = bound
        .search::<UserEntry>(
            "OU=Specialists,DC=company,DC=com",
            SearchRequestScope::WholeSubtree,
            SearchRequestDerefAliases::DerefAlways,
            search_filter,
        )
        .unwrap();
    for UserEntry {
        sam_account_name,
        company,
        ..
    } in search_results.flatten()
    {
        println!("{sam_account_name} works for {company}");
    }
}

#[derive(Entry)]
struct UserEntry {
    #[lapdog(rename = "sAMAccountName")]
    sam_account_name: String,
    company: String,
    #[lapdog(multiple, rename = "objectClass")]
    object_class: Vec<String>,
}
