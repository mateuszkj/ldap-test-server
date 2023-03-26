# LDAP server for Rust integration testing

This crate allow starting isolated OpenLDAP (slapd) server in integration tests.

OpenLDAP server is created in temporary directory and uses random free port.


# Example

```rust
use ldap_test_server::LdapServerBuilder;

#[tokio::main]
async fn main() {
    let server = LdapServerBuilder::new("dc=planetexpress,dc=com")
        // add LDIF to database before LDAP server is started
        .add(1, "dn: dc=planetexpress,dc=com
objectclass: dcObject
objectclass: organization
o: Planet Express
dc: planetexpress

dn: ou=people,dc=planetexpress,dc=com
objectClass: top
objectClass: organizationalUnit
description: Planet Express crew
ou: people")
        // init databases and started LDAP server
        .run()
        .await;

        // Add entity to running LDAP server
        server.add(r##"dn: cn=Turanga Leela,ou=people,dc=planetexpress,dc=com
objectClass: inetOrgPerson
objectClass: organizationalPerson
objectClass: person
objectClass: top
cn: Turanga Leela
sn: Turanga
givenName: Leela"##).await;
}
```

# Dependencies

This crate depends on system commands that has to be available from $PATH
 - slapdd
 - slapd
 - ldapadd
 - ldapmodiy
 - ldapdelete

## How to install slpad and ldap-utils on Ubuntu

```sh
DEBIAN_FRONTEND=noninteractive sudo apt-get install -y slapd ldap-utils
sudo systemctl stop slapd
sudo systemctl disable slapd
sudo ln -s /etc/apparmor.d/usr.sbin.slapd /etc/apparmor.d/disable/
sudo apparmor_parser -R /etc/apparmor.d/usr.sbin.slapd
```

## License

Licensed under either of:

* Apache License, Version 2.0 ([LICENSE-APACHE](LICENSE-APACHE)), or
* MIT license ([LICENSE-MIT](LICENSE-MIT))
