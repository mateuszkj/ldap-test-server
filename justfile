default:
	@just --list --justfile {{justfile()}}

# Install development dependences.
install-dev:
	cargo install --git https://github.com/DevinR528/cargo-sort.git
	DEBIAN_FRONTEND=noninteractive sudo apt-get install -y slapd ldap-utils
	sudo systemctl stop slapd
	sudo systemctl disable slapd
	sudo ln -s /etc/apparmor.d/usr.sbin.slapd /etc/apparmor.d/disable/
	sudo apparmor_parser -R /etc/apparmor.d/usr.sbin.slapd

	
# Rust cargo check
check:
	cargo check --tests

# Run formatter
fmt:
	cargo fmt
	cargo sort -w

# Run fmt and clippy
lint: fmt check
	cargo clippy --tests -- -D warnings

# Run tests
test:
	cargo test

# Test if creates can be publushed
publush-dry-run:
	cargo publish -p ldap-test-server --dry-run
	cargo publish -p ldap-test-server-cli --dry-run
