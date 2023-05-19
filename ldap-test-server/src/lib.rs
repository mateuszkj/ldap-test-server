//! This crate allow running isolated OpenLDAP (slapd) server in integration tests.
//!
//! # Examples
//!
//! ```
//! use ldap_test_server::{LdapServerConn, LdapServerBuilder};
//!
//! # #[tokio::main(flavor = "current_thread")]
//! # async fn main() {
//! let server: LdapServerConn = LdapServerBuilder::new("dc=planetexpress,dc=com")
//!         // add LDIF to database before LDAP server is started
//!         .add(1, "dn: dc=planetexpress,dc=com
//! objectclass: dcObject
//! objectclass: organization
//! o: Planet Express
//! dc: planetexpress
//!
//! dn: ou=people,dc=planetexpress,dc=com
//! objectClass: top
//! objectClass: organizationalUnit
//! description: Planet Express crew
//! ou: people")
//!         // init databases and started LDAP server
//!         .run()
//!         .await;
//!
//! // Add entity to running LDAP server
//! server.add(r##"dn: cn=Turanga Leela,ou=people,dc=planetexpress,dc=com
//! objectClass: inetOrgPerson
//! objectClass: organizationalPerson
//! objectClass: person
//! objectClass: top
//! cn: Turanga Leela
//! sn: Turanga
//! givenName: Leela"##).await;
//! # }
//! ```
//!
#![warn(missing_docs)]
use dircpy::copy_dir;
use std::convert::AsRef;
use std::path::Path;
use tempfile::TempDir;
use tokio::process::{Child, Command};
use tokio::task;
use tracing::{debug, warn};

mod builder;

pub use builder::LdapServerBuilder;

/// Connection to running LDAP server
#[derive(Debug)]
pub struct LdapServerConn {
    url: String,
    host: String,
    port: u16,
    ssl_url: String,
    ssl_port: u16,
    ssl_cert_pem: String,
    #[allow(unused)]
    dir: TempDir,
    base_dn: String,
    root_dn: String,
    root_pw: String,
    server: Child,
}

impl LdapServerConn {
    /// Return URL (schema=ldap, host and port) to this LDAP server
    pub fn url(&self) -> &str {
        &self.url
    }

    /// Hostname of this LDAP server
    pub fn host(&self) -> &str {
        &self.host
    }

    /// TCP port number of this LDAP server
    pub fn port(&self) -> u16 {
        self.port
    }

    /// Return URL (schema=ldaps, host and port) to this LDAP server
    pub fn ssl_url(&self) -> &str {
        &self.ssl_url
    }

    /// SSL (ldaps) TCP port number of this LDAP server
    pub fn ssl_port(&self) -> u16 {
        self.ssl_port
    }

    /// PEM Certificate for ssl port
    pub fn ssl_cert_pem(&self) -> &str {
        &self.ssl_cert_pem
    }

    /// Base DN of this LDAP server
    pub fn base_dn(&self) -> &str {
        &self.base_dn
    }

    /// Administrator account of this LDAP server
    pub fn root_dn(&self) -> &str {
        &self.root_dn
    }

    /// Password for administrator server of this LDAP server
    pub fn root_pw(&self) -> &str {
        &self.root_pw
    }

    /// LDAP server directory location
    pub fn server_dir(&self) -> &Path {
        self.dir.path()
    }

    /// Clone LDAP server files to new location
    pub async fn clone_to_dir<P: AsRef<Path>>(&self, desc: P) {
        let src = self.dir.path().to_path_buf();
        let dst = desc.as_ref().to_path_buf();
        task::spawn_blocking(move || {
            copy_dir(&src, &dst).unwrap();
        })
        .await
        .unwrap();
    }

    /// Apply LDIF from text
    ///
    /// # Examples
    ///
    /// ```
    /// # use ldap_test_server::LdapServerBuilder;
    /// #
    /// # #[tokio::main(flavor = "current_thread")]
    /// # async fn main() {
    /// # let server = LdapServerBuilder::new("dc=planetexpress,dc=com")
    /// #     .add(1, "dn: dc=planetexpress,dc=com
    /// # objectclass: dcObject
    /// # objectclass: organization
    /// # o: Planet Express
    /// # dc: planetexpress")
    /// #     .run().await;
    /// #
    /// server.add("dn: cn=Philip J. Fry,dc=planetexpress,dc=com
    /// objectClass: inetOrgPerson
    /// objectClass: organizationalPerson
    /// objectClass: person
    /// objectClass: top
    /// cn: Philip J. Fry
    /// givenName: Philip
    /// sn: Fry").await;
    /// # }
    /// ```
    pub async fn add(&self, ldif_text: &str) -> &Self {
        let tmp_ldif = self.dir.path().join("tmp.ldif");
        tokio::fs::write(&tmp_ldif, ldif_text).await.unwrap();
        self.add_file(tmp_ldif).await
    }

    /// Apply LDIF from file
    pub async fn add_file<P: AsRef<Path>>(&self, file: P) -> &Self {
        self.load_ldif_file("ldapadd", file, self.root_dn(), self.root_pw())
            .await
    }

    /// Apply modification LDIF from text
    ///
    /// # Examples
    ///
    /// ```
    /// # use ldap_test_server::LdapServerBuilder;
    /// #
    /// # #[tokio::main(flavor = "current_thread")]
    /// # async fn main() {
    /// # let server = LdapServerBuilder::new("dc=planetexpress,dc=com")
    /// #     .add(1, "dn: dc=planetexpress,dc=com
    /// # objectclass: dcObject
    /// # objectclass: organization
    /// # o: Planet Express
    /// # dc: planetexpress")
    /// #     .run().await;
    /// #
    /// # server.add("dn: cn=Philip J. Fry,dc=planetexpress,dc=com
    /// # objectClass: inetOrgPerson
    /// # objectClass: organizationalPerson
    /// # objectClass: person
    /// # objectClass: top
    /// # cn: Philip J. Fry
    /// # givenName: Philip
    /// # sn: Fry").await;
    /// #
    /// server.modify("dn: cn=Philip J. Fry,dc=planetexpress,dc=com
    /// changetype: modify
    /// add: displayName
    /// displayName: Philip J. Fry").await;
    /// # }
    /// ```
    pub async fn modify(&self, ldif_text: &str) -> &Self {
        let tmp_ldif = self.dir.path().join("tmp.ldif");
        tokio::fs::write(&tmp_ldif, ldif_text).await.unwrap();
        self.modify_file(tmp_ldif).await
    }

    /// Apply modification LDIF from file
    pub async fn modify_file<P: AsRef<Path>>(&self, file: P) -> &Self {
        self.load_ldif_file("ldapmodify", file, self.root_dn(), self.root_pw())
            .await
    }

    /// Apply deletion LDIF from text
    ///
    /// # Examples
    ///
    /// ```
    /// # use ldap_test_server::LdapServerBuilder;
    /// #
    /// # #[tokio::main(flavor = "current_thread")]
    /// # async fn main() {
    /// # let server = LdapServerBuilder::new("dc=planetexpress,dc=com")
    /// #     .add(1, "dn: dc=planetexpress,dc=com
    /// # objectclass: dcObject
    /// # objectclass: organization
    /// # o: Planet Express
    /// # dc: planetexpress")
    /// #     .run().await;
    /// #
    /// # server.add("dn: cn=Philip J. Fry,dc=planetexpress,dc=com
    /// # objectClass: inetOrgPerson
    /// # objectClass: organizationalPerson
    /// # objectClass: person
    /// # objectClass: top
    /// # cn: Philip J. Fry
    /// # givenName: Philip
    /// # sn: Fry").await;
    /// #
    /// server.delete("dn: cn=Philip J. Fry,dc=planetexpress,dc=com
    /// changetype: delete").await;
    /// # }
    /// ```
    pub async fn delete(&self, ldif_text: &str) -> &Self {
        let tmp_ldif = self.dir.path().join("tmp.ldif");
        tokio::fs::write(&tmp_ldif, ldif_text).await.unwrap();
        self.modify_file(tmp_ldif).await
    }

    /// Apply deletion LDIF from file
    pub async fn delete_file<P: AsRef<Path>>(&self, file: P) -> &Self {
        self.load_ldif_file("ldapdelete", file, self.root_dn(), self.root_pw())
            .await
    }

    async fn load_ldif_file<P: AsRef<Path>>(
        &self,
        command: &str,
        file: P,
        binddn: &str,
        password: &str,
    ) -> &Self {
        let file = file.as_ref();

        let output = Command::new(command)
            .args(["-x", "-D", binddn, "-w", password, "-H", self.url(), "-f"])
            .arg(file)
            .output()
            .await
            .expect("failed to load ldap file");

        if !output.status.success() {
            panic!(
                "{command} command exited with error {}, stdout: {}, stderr: {} on file {}",
                output.status,
                String::from_utf8_lossy(&output.stdout),
                String::from_utf8_lossy(&output.stderr),
                file.display()
            );
        }

        self
    }
}

impl Drop for LdapServerConn {
    fn drop(&mut self) {
        if let Err(e) = self.server.start_kill() {
            warn!(
                "failed to kill slapd server: {}, pid: {:?}",
                e,
                self.server.id()
            );
        } else {
            debug!("killed slapd server pid: {:?}", self.server.id());
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Instant;

    #[tokio::test]
    async fn run_slapd() {
        let started = Instant::now();

        let server = LdapServerBuilder::new("dc=planetexpress,dc=com")
            .add_system_file(0, "pmi.ldif")
            .add(
                1,
                "dn: dc=planetexpress,dc=com
objectclass: dcObject
objectclass: organization
o: Planet Express
dc: planetexpress

dn: ou=people,dc=planetexpress,dc=com
objectClass: top
objectClass: organizationalUnit
description: Planet Express crew
ou: people",
            )
            .add_file(1, concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fry.ldif"))
            .run()
            .await;

        server
            .add(
                "dn: cn=Amy Wong+sn=Kroker,ou=people,dc=planetexpress,dc=com
objectClass: top
objectClass: person
objectClass: organizationalPerson
objectClass: inetOrgPerson
cn: Amy Wong
sn: Kroker
description: Human
givenName: Amy
mail: amy@planetexpress.com
ou: Intern
uid: amy",
            )
            .await;

        println!("Server started in {} ms", started.elapsed().as_millis());
    }
}
