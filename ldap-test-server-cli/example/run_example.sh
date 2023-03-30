#!/bin/sh

set -e

cargo run -p ldap-test-server-cli -r -- --bind-addr localhost --port 8389 -b "dc=planetexpress,dc=com" -s schema/ -d data/
