use cucumber::{given, then, when, World};
use derivative::Derivative;
use ldap3::{Ldap, LdapConnAsync, LdapConnSettings, Scope};
use ldap_test_server::LdapServerBuilder;
use ldap_test_server::LdapServerConn;
use native_tls::{Certificate, TlsConnector};

const LDAP_BASE_DN: &str = "dc=planetexpress,dc=com";

#[derive(Derivative, Default, World)]
#[derivative(Debug)]
pub struct LdapWorld {
    /// LDAP server builder
    builder: Option<LdapServerBuilder>,
    /// Ldap server
    server: Option<LdapServerConn>,

    /// Client connection to ldap server
    #[derivative(Debug = "ignore")]
    client: Option<Ldap>,

    login_result: Option<ldap3::result::Result<()>>,
    search_results: Vec<ldap3::ResultEntry>,
}

impl LdapWorld {
    async fn connect_to_ldap(&mut self) {
        let server = self.server.as_ref().unwrap();
        let cert = Certificate::from_pem(server.ssl_cert_pem().as_bytes()).unwrap();
        let settings = LdapConnSettings::new().set_connector(
            TlsConnector::builder()
                .add_root_certificate(cert)
                .build()
                .expect("tls connector"),
        );
        let (conn, ldap) = LdapConnAsync::with_settings(settings, server.ssl_url())
            .await
            .unwrap();
        ldap3::drive!(conn);
        self.client = Some(ldap);
    }
}

#[given("Created LDAP database")]
fn ldap_database_created(world: &mut LdapWorld) {
    world.builder = Some(LdapServerBuilder::new(LDAP_BASE_DN).add(
        1,
        &format!(
            r#"dn: {LDAP_BASE_DN}
objectclass: dcObject
objectclass: organization
o: Planet Express
dc: planetexpress"#
        ),
    ));
}

#[given(expr = "LDAP database initialized with empty Organizational Unit \\(ou\\) named {string}")]
fn ldap_add_organization_unit(world: &mut LdapWorld, ou: String) {
    let builder = world.builder.take().unwrap();
    let ldif = format!(
        r#"dn: ou={ou},{LDAP_BASE_DN}
objectClass: top
objectClass: organizationalUnit
description: Planet Express {ou}
ou: {ou}""#
    );

    world.builder = Some(builder.add(1, &ldif));
}

#[given("LDAP server is started")]
async fn ldap_started(world: &mut LdapWorld) {
    let builder = world.builder.take().unwrap();
    world.server = Some(builder.run().await);
}

#[given(expr = "Application added person {string} to OU {string} with LDIF")]
async fn ldap_add_person(world: &mut LdapWorld, person: String, group: String) {
    let ldif = format!(
        r##"dn: cn={person},ou={group},{LDAP_BASE_DN}
objectClass: inetOrgPerson
objectClass: organizationalPerson
objectClass: person
objectClass: top
cn: {person}
sn: {person}
"##
    );
    let server = world.server.as_ref().unwrap();
    server.add(&ldif).await;
}

#[given(
    expr = "Application updated person {string} in OU {string} with displayName {string} with LDIF"
)]
async fn ldap_modify_person(
    world: &mut LdapWorld,
    person: String,
    group: String,
    display_name: String,
) {
    let ldif = format!(
        r##"dn: cn={person},ou={group},{LDAP_BASE_DN}
changetype: modify
add: displayName
displayName: {display_name}
"##
    );
    let server = world.server.as_ref().unwrap();
    server.modify(&ldif).await;
}

#[given(expr = "Application deleted person {string} in OU {string} with LDIF")]
async fn ldap_delete_person(world: &mut LdapWorld, person: String, group: String) {
    let ldif = format!(
        r##"dn: cn={person},ou={group},{LDAP_BASE_DN}
changetype: delete
"##
    );
    let server = world.server.as_ref().unwrap();
    server.delete(&ldif).await;
}

#[when("Application tries to login to LDAP server")]
async fn app_login_to_ldap(world: &mut LdapWorld) {
    let server = world.server.as_ref().unwrap();
    let user = server.root_dn().to_string();
    let password = server.root_pw().to_string();
    app_login_with_user_password(world, &user, &password).await;
}

#[when("Application simple binds to server with invalid password")]
async fn app_login_to_ldap_invalid_password(world: &mut LdapWorld) {
    let server = world.server.as_ref().unwrap();
    let user = server.root_dn().to_string();
    let password = format!("{}_invalid", server.root_pw());
    app_login_with_user_password(world, &user, &password).await;
}

async fn app_login_with_user_password(world: &mut LdapWorld, user: &str, pass: &str) {
    world.connect_to_ldap().await;
    let client = world.client.as_mut().unwrap();
    let result = client.simple_bind(user, pass).await.unwrap().success();

    world.login_result = Some(result.map(|_| ()));
}

#[when(expr = "Application queries LDAP server with {string}")]
async fn app_query_ldap(world: &mut LdapWorld, filter: String) {
    app_login_to_ldap(world).await;
    let client = world.client.as_mut().unwrap();
    let (list, _) = client
        .search(LDAP_BASE_DN, Scope::Subtree, &filter, vec!["*"])
        .await
        .unwrap()
        .success()
        .unwrap();
    world.search_results = list;
}

#[when(expr = "Application adds LDIF to LDAP database with AD compatibility layer")]
fn ldap_add_active_directory(world: &mut LdapWorld) {
    let builder = world.builder.take().unwrap();
    let ldif = r##"dn: cn=user,cn=schema,cn=config
objectClass: olcSchemaConfig
cn: user
#
olcAttributeTypes: ( 1.2.840.113556.4.221
  NAME 'sAMAccountName'
  SYNTAX '1.3.6.1.4.1.1466.115.121.1.15'
  EQUALITY caseIgnoreMatch
  SUBSTR caseIgnoreSubstringsMatch
  SINGLE-VALUE )
#
olcObjectClasses: ( 1.2.840.113556.1.5.9
  NAME 'user'
  SUP top
  AUXILIARY
  MAY ( sAMAccountName ))"##;

    world.builder = Some(builder.add(0, ldif));
}

#[then(expr = "There is {int} result\\(s\\)")]
fn app_got_n_results(world: &mut LdapWorld, n: usize) {
    assert_eq!(world.search_results.len(), n);
}

#[then("Successfully logged")]
fn app_successfully_logged(world: &mut LdapWorld) {
    let result = world.login_result.as_ref().unwrap();
    assert!(result.is_ok(), "Expected OK got error {result:?}");
}

#[then(expr = "Got error {string}")]
fn app_error(world: &mut LdapWorld, expected_error: String) {
    let err = world
        .login_result
        .as_ref()
        .unwrap()
        .as_ref()
        .unwrap_err()
        .to_string();
    assert!(
        err.contains(&expected_error),
        "Expected string containing {expected_error}, got {err}"
    );
}

#[then(expr = "Application can add person with filled sAMAccountName attribute")]
async fn ldap_add_person_to_active_directory(world: &mut LdapWorld) {
    let builder = world.builder.take().unwrap();
    let ldif = r##"dn: cn=Turanga Leela,ou=people,dc=planetexpress,dc=com
objectClass: inetOrgPerson
objectClass: organizationalPerson
objectClass: person
objectClass: top
objectClass: user
cn: Turanga Leela
sn: Turanga
description: Mutant
employeeType: Captain
employeeType: Pilot
givenName: Leela
sAMAccountName: l.turanga
"##;

    world.builder = Some(builder.add(1, ldif));
    ldap_started(world).await;
}

#[tokio::main(flavor = "current_thread")]
async fn main() {
    let summary = LdapWorld::cucumber()
        .max_concurrent_scenarios(4)
        .run("tests/features/ldap_server.feature")
        .await;

    assert_eq!(summary.scenarios_stats().failed, 0);
    assert_eq!(summary.scenarios_stats().skipped, 0);
}
