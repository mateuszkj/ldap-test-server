default:
    @just --list --justfile {{ justfile() }}

# Install development dependences.
install-dev:
    cargo install --locked cargo-llvm-cov cargo-mutants cargo-deny cargo-edit cargo-sort-derives typos-cli cargo-udeps cargo-msrv
    cargo install --locked --git https://github.com/DevinR528/cargo-sort.git
    DEBIAN_FRONTEND=noninteractive sudo apt-get install -y slapd ldap-utils
    sudo systemctl stop slapd
    sudo systemctl disable slapd
    sudo ln -fs /etc/apparmor.d/usr.sbin.slapd /etc/apparmor.d/disable/
    sudo apparmor_parser -R /etc/apparmor.d/usr.sbin.slapd || true

# Run formatter
fmt:
    cargo fmt
    cargo sort -w
    cargo sort-derives

# Run fmt and clippy
lint: fmt
    cargo check --tests
    typos
    cargo clippy -- -D warnings
    cargo clippy --tests -- -D warnings
    cargo deny check
    cargo +nightly udeps
    cargo msrv verify --path ldap-test-server/
    cargo msrv verify --path ladp-test-server-cli/

# Run tests
test:
    cargo test

# Find minimal supported rust version
find-msrv:
    cargo msrv find --path ldap-test-server/

# Find minimal supported rust version for cli.
find-msrv-cli:
    cargo msrv find --path ldap-test-server-cli/

# Test if creates can be publushed
publish-dry-run:
    cargo publish -p ldap-test-server --dry-run
    cargo publish -p ldap-test-server-cli --dry-run
