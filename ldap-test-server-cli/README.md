#  Run local LDAP server for integration testing

This tool allow to start local OpenLDAP (slapd) server for integration tests.

OpenLDAP server is created in temporary directory and uses random free port.

## Installation

Deepness (Ubuntu)
```sh
DEBIAN_FRONTEND=noninteractive sudo apt-get install -y slapd ldap-utils openssl
sudo systemctl stop slapd
sudo systemctl disable slapd
sudo ln -s /etc/apparmor.d/usr.sbin.slapd /etc/apparmor.d/disable/
sudo apparmor_parser -R /etc/apparmor.d/usr.sbin.slapd
```

Install via cargo
``
cargo install ldap-test-server-cli
``

## Run server

```sh
ldap-test-server-cli -b "dc=planetexpress,dc=com" 
```

## Example

You can find in example [directory](./example/)

## Usage

```sh
Usage: ldap-test-server-cli [OPTIONS]

Options:
  -b, --base-dn <BASE_DN>        Base DN [default: dc=planetexpress,dc=com]
      --bind-addr <BIND_ADDR>    Bind ldap server on address
      --port <PORT>              Port of ldap server
      --ssl-port <SSL_PORT>      Port of ldaps server
  -s, --schema-dir <SCHEMA_DIR>  Directory of ldif files with schema which be installed in database 0
  -d, --data-dir <DATA_DIR>      Directory of ldif files with data which be installed in database 1
  -h, --help                     Print help
  -V, --version                  Print version
```

## License

Licensed under either of:

* Apache License, Version 2.0 ([LICENSE-APACHE](../LICENSE-APACHE)), or
* MIT license ([LICENSE-MIT](../LICENSE-MIT))
