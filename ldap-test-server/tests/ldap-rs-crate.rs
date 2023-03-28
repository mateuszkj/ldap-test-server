use futures_util::TryStreamExt;
use ldap_rs::{LdapClient, SearchRequest, SearchRequestScope};
use ldap_test_server::LdapServerBuilder;

#[tokio::test]
async fn test_bind() {
    let server = LdapServerBuilder::new("dc=kondej,dc=net").run().await;

    let mut client = LdapClient::builder(server.host())
        .port(server.port())
        .connect()
        .await
        .unwrap();
    client
        .simple_bind(server.root_dn(), server.root_pw())
        .await
        .unwrap();

    let authz = client.whoami().await.unwrap();
    assert_eq!(authz.as_deref(), Some("dn:cn=admin,dc=kondej,dc=net"));

    client.unbind().await.unwrap();
}

#[tokio::test]
async fn test_forbidden_anonymous_access() {
    let server = LdapServerBuilder::new("dc=kondej,dc=net").run().await;

    let mut client = LdapClient::builder(server.host())
        .port(server.port())
        .connect()
        .await
        .unwrap();

    let result = client
        .search(
            SearchRequest::builder()
                .base_dn(server.base_dn())
                .scope(SearchRequestScope::WholeSubtree)
                .filter("(objectClass=*)")
                .build()
                .unwrap(),
        )
        .await
        .unwrap();
    let items = result.try_collect::<Vec<_>>().await;
    let error = match items {
        Ok(_) => panic!("expected a error but got data"),
        Err(e) => e,
    };

    assert_eq!(
        format!("{error:?}"),
        r#"OperationFailed(OperationError { result_code: UnwillingToPerform, matched_dn: "", diagnostic_message: "authentication required" })"#
    );
}

#[tokio::test]
async fn test_query() {
    let server = LdapServerBuilder::new("dc=planetexpress,dc=com")
        .run()
        .await;

    server
        .add(
            "dn: dc=planetexpress,dc=com
objectclass: dcObject
objectclass: organization
o: Planet Express
dc: planetexpress

dn: ou=people,dc=planetexpress,dc=com
objectClass: top
objectClass: organizationalUnit
description: Planet Express crew
ou: people",
        )
        .await
        .add_file(concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fry.ldif"))
        .await;

    let mut client = LdapClient::builder(server.host())
        .port(server.port())
        .connect()
        .await
        .unwrap();
    client
        .simple_bind(server.root_dn(), server.root_pw())
        .await
        .unwrap();

    let result = client
        .search(
            SearchRequest::builder()
                .base_dn(server.base_dn())
                .scope(SearchRequestScope::WholeSubtree)
                .filter("(objectClass=inetOrgPerson)")
                .build()
                .unwrap(),
        )
        .await
        .unwrap();

    let items = result.try_collect::<Vec<_>>().await.unwrap();
    assert_eq!(items.len(), 1);
    assert_eq!(
        items[0].dn,
        "cn=Philip J. Fry,ou=people,dc=planetexpress,dc=com"
    );

    server
        .add(
            "dn: cn=Turanga Leela,ou=people,dc=planetexpress,dc=com
objectClass: inetOrgPerson
objectClass: organizationalPerson
objectClass: person
objectClass: top
cn: Turanga Leela
sn: Turanga
description: Mutant
employeeType: Captain
employeeType: Pilot
givenName: Leela",
        )
        .await;

    let item = client
        .search_one(
            SearchRequest::builder()
                .base_dn(server.base_dn())
                .scope(SearchRequestScope::WholeSubtree)
                .filter("(&(objectClass=inetOrgPerson)(sn=Turanga))")
                .build()
                .unwrap(),
        )
        .await
        .unwrap()
        .unwrap();

    assert_eq!(
        item.dn,
        "cn=Turanga Leela,ou=people,dc=planetexpress,dc=com"
    );

    client.unbind().await.unwrap();
}
