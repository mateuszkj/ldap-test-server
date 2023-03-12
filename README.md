# LDAP server for Rust integration testing


## How to install slpad on Ubuntu

```sh
DEBIAN_FRONTEND=noninteractive sudo apt-get install -y slapd ldap-utils
sudo systemctl stop slapd
sudo systemctl disable slapd
sudo ln -s /etc/apparmor.d/usr.sbin.slapd /etc/apparmor.d/disable/
sudo apparmor_parser -R /etc/apparmor.d/usr.sbin.slapd
```
