#!/bin/sh

set -e

cargo run -p ldap-test-server-cli -r -- --bind-addr 0.0.0.0 --port 8389 -b "dc=planetexpress,dc=com" -s schema/ -d data/
