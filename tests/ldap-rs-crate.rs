use ldap_rs::LdapClient;
use ldap_test_server::LdapServerBuilder;

#[tokio::test]
async fn test_bind() {
    let server = LdapServerBuilder::new("dc=kondej,dc=net").run();

    let mut client = LdapClient::builder(server.host())
        .port(server.port())
        .connect()
        .await
        .unwrap();
    client
        .simple_bind(server.root_dn(), server.root_pw())
        .await
        .unwrap();
    println!("Bind succeeded!");

    let authz = client.whoami().await.unwrap();
    println!("Authz: {authz:?}");

    client.unbind().await.unwrap();
    println!("Unbind succeeded!");
}
