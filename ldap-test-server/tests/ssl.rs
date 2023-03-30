use ldap_rs::{Certificate, LdapClient, TlsOptions};
use ldap_test_server::LdapServerBuilder;

#[tokio::test]
async fn test_bind_over_ssl() {
    let server = LdapServerBuilder::new("dc=kondej,dc=net").run().await;

    let tls =
        TlsOptions::tls().ca_cert(Certificate::from_pem(server.ssl_cert_pem().as_ref()).unwrap());

    let mut client = LdapClient::builder(server.host())
        .port(server.ssl_port())
        .tls_options(tls)
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
