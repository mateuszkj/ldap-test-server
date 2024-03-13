# Tools for testing with OpenLDAP server

[Crate for running integration tests](./ldap-test-server/README.md)

[Command line tools for starting server](./ldap-test-server-cli/README.md)

# Dependencies

This crate depends on system commands that has to be available from $PATH
 - slapd
 - ldapadd
 - ldapmodify
 - ldapdelete

## How to install slpad and ldap-utils on Ubuntu

```sh
DEBIAN_FRONTEND=noninteractive sudo apt-get install -y slapd ldap-utils
sudo systemctl stop slapd
sudo systemctl disable slapd
sudo ln -s /etc/apparmor.d/usr.sbin.slapd /etc/apparmor.d/disable/
sudo apparmor_parser -R /etc/apparmor.d/usr.sbin.slapd
```

or run:
```
just install-dev
```

## License

Licensed under either of:

* Apache License, Version 2.0 ([LICENSE-APACHE](LICENSE-APACHE)), or
* MIT license ([LICENSE-MIT](LICENSE-MIT))
