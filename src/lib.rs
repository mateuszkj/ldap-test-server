use std::convert::AsRef;
use std::path::{Path, PathBuf};
use std::time::Duration;
use std::{net::ToSocketAddrs, process::Stdio};
use tokio::io::AsyncBufReadExt;
use tokio::net::TcpStream;
use tokio::process::{Child, Command};
use tokio::time::{sleep, timeout};
use url::Url;

use tempfile::{tempdir, TempDir};

const INIT_LDIF: &str = include_str!("init.ldif");
const POSSIBLE_SCHEMA_DIR: &[&str] = &[
    "/etc/ldap/schema",
    "/usr/local/etc/openldap/schema",
    "/etc/openldap/schema/",
];

#[derive(Debug)]
enum LdapFile {
    SystemSchema(String),
    File { template: bool, file: PathBuf },
    Text { template: bool, content: String },
}

pub struct LdapServerBuilder {
    base_dn: String,
    root_dn: String,
    root_pw: String,
    includes: Vec<(u8, LdapFile)>,
}

impl LdapServerBuilder {
    /// Init empty builder
    pub fn empty(
        base_dn: impl Into<String>,
        root_dn: impl Into<String>,
        root_pw: impl Into<String>,
    ) -> Self {
        let base_dn = base_dn.into();
        let root_dn = root_dn.into();
        let root_pw = root_pw.into();

        Self {
            base_dn,
            root_dn,
            root_pw,
            includes: vec![],
        }
    }

    /// Init builder with simple database
    pub fn new(base_dn: &str) -> Self {
        let root_dn = format!("cn=admin,{base_dn}");
        let root_pw = "secret".to_string();
        LdapServerBuilder::empty(base_dn, root_dn, root_pw).add_template_ldif(0, INIT_LDIF)
    }

    /// Add system LDIF from schema dir installed by slapd (usually in /etc/ldap/schema directory)
    pub fn add_system_ldif(mut self, dbnum: u8, file: &str) -> Self {
        self.includes
            .push((dbnum, LdapFile::SystemSchema(file.to_string())));
        self
    }

    /// Add LDIF file with text content
    pub fn add_ldif(mut self, dbnum: u8, content: &str) -> Self {
        self.includes.push((
            dbnum,
            LdapFile::Text {
                template: false,
                content: content.to_string(),
            },
        ));
        self
    }

    /// Add LDIF file
    pub fn add_ldif_file<P: AsRef<Path>>(mut self, dbnum: u8, file: P) -> Self {
        self.includes.push((
            dbnum,
            LdapFile::File {
                template: true,
                file: file.as_ref().to_path_buf(),
            },
        ));
        self
    }

    /// Add LDIF file with text content as template
    pub fn add_template_ldif(mut self, dbnum: u8, content: &str) -> Self {
        self.includes.push((
            dbnum,
            LdapFile::Text {
                template: true,
                content: content.to_string(),
            },
        ));
        self
    }

    /// Add LDIF file as template
    pub fn add_template_ldif_file<P: AsRef<Path>>(mut self, dbnum: u8, file: P) -> Self {
        self.includes.push((
            dbnum,
            LdapFile::File {
                template: true,
                file: file.as_ref().to_path_buf(),
            },
        ));
        self
    }

    async fn build_config(includes: Vec<(u8, LdapFile)>, tmp_dir: &Path, system_schema_dir: &Path) {
        for (idx, (dbnum, include)) in includes.into_iter().enumerate() {
            let file = match include {
                LdapFile::SystemSchema(file) => system_schema_dir.join(file),
                LdapFile::File {
                    template: false,
                    file,
                } => file,
                LdapFile::Text {
                    template: false,
                    content,
                } => {
                    let tmp_ldif = tmp_dir.join(format!("tmp_{idx}.ldif"));
                    tokio::fs::write(&tmp_ldif, content).await.unwrap();
                    tmp_ldif
                }
                LdapFile::File { template: true, .. } | LdapFile::Text { template: true, .. } => {
                    panic!("Templates should be already built");
                }
            };

            LdapServerBuilder::load_ldif(tmp_dir, dbnum, file).await;
        }
    }

    async fn load_ldif(config_dir: &Path, dbnum: u8, file: PathBuf) {
        let db_number = dbnum.to_string();
        // load slapd configuration
        let output = Command::new("slapadd")
            .arg("-F")
            .arg(".")
            .arg("-n")
            .arg(db_number)
            .arg("-l")
            .arg(&file)
            .current_dir(config_dir)
            .output()
            .await
            .expect("failed to execute slapadd");

        if !output.status.success() {
            panic!(
                "slapadd command exited with error {}, stdout: {}, stderr: {} on file {}",
                output.status,
                String::from_utf8_lossy(&output.stdout),
                String::from_utf8_lossy(&output.stderr),
                file.display()
            );
        }
    }

    async fn build_templates(&mut self, system_schema_dir: &Path) {
        let schema_dir_url = Url::from_file_path(system_schema_dir).unwrap();

        for (_, include) in &mut self.includes {
            let content = match include {
                LdapFile::File {
                    template: true,
                    file,
                } => tokio::fs::read_to_string(file).await.unwrap(),
                LdapFile::Text {
                    template: true,
                    content,
                } => std::mem::take(content),
                _ => continue,
            };

            let new_content = content
                .replace("@SCHEMADIR@", schema_dir_url.as_ref())
                .replace("@BASEDN@", &self.base_dn)
                .replace("@ROOTDN@", &self.root_dn)
                .replace("@ROOTPW@", &self.root_pw);

            *include = LdapFile::Text {
                template: false,
                content: new_content,
            };
        }
    }

    pub async fn run(mut self) -> LdapServerConn {
        let schema_dir = find_slapd_schema_dir()
            .await
            .expect("no slapd schema directory found. Is openldap server installed?");
        let host = "localhost".to_string();
        let port = portpicker::pick_unused_port().expect("no free tcp port to bind");
        let url = format!("ldap://{host}:{port}");
        let dir = tempdir().unwrap();

        self.build_templates(schema_dir).await;
        LdapServerBuilder::build_config(self.includes, dir.path(), schema_dir).await;

        // lauch slapd server
        let mut server = Command::new("slapd")
            .args(["-F", ".", "-d", "2048", "-h", &url])
            .stderr(Stdio::piped())
            .current_dir(&dir)
            .spawn()
            .unwrap();

        // wait unitl slapd server has started
        let stderr = server.stderr.take().unwrap();
        let mut lines = tokio::io::BufReader::new(stderr).lines();
        let timeouted = timeout(Duration::from_secs(5), async {
            while let Some(line) = lines.next_line().await.unwrap() {
                if line.ends_with("slapd starting") {
                    return true;
                }
            }
            false
        })
        .await;

        if timeouted.is_err() || timeouted == Ok(false) {
            let _ = server.kill().await;
            panic!("Failed to start slapd server");
        }

        let timeouted = timeout(Duration::from_secs(2), async {
            while !is_tcp_port_open(&host, port).await {
                println!("tcp port {port} is not open yet, waiting...");
                sleep(Duration::from_micros(100)).await;
            }
        })
        .await;

        if timeouted.is_err() {
            let _ = server.kill().await;
            panic!("Failed to start slapd server, port {port} not open");
        }

        println!("Started ldap server on {url}");

        LdapServerConn {
            url,
            host,
            port,
            dir,
            base_dn: self.base_dn,
            root_dn: self.root_dn,
            root_pw: self.root_pw,
            server,
        }
    }
}

async fn find_slapd_schema_dir() -> Option<&'static Path> {
    for dir in POSSIBLE_SCHEMA_DIR {
        let dir: &Path = dir.as_ref();
        if tokio::fs::metadata(dir)
            .await
            .map(|m| m.is_dir())
            .unwrap_or(false)
        {
            return Some(dir);
        }
    }
    None
}

async fn is_tcp_port_open(host: &str, port: u16) -> bool {
    let addr = (host, port).to_socket_addrs().unwrap().next().unwrap();
    let Ok(sock) = timeout(Duration::from_secs(1), TcpStream::connect(&addr)).await else { return false };
    sock.is_ok()
}

#[derive(Debug)]
pub struct LdapServerConn {
    url: String,
    host: String,
    port: u16,
    #[allow(unused)]
    dir: TempDir,
    base_dn: String,
    root_dn: String,
    root_pw: String,
    server: Child,
}

impl LdapServerConn {
    pub fn url(&self) -> &str {
        &self.url
    }

    pub fn host(&self) -> &str {
        &self.host
    }

    pub fn port(&self) -> u16 {
        self.port
    }

    pub fn base_dn(&self) -> &str {
        &self.base_dn
    }

    pub fn root_dn(&self) -> &str {
        &self.root_dn
    }

    pub fn root_pw(&self) -> &str {
        &self.root_pw
    }

    pub async fn add_ldif(&self, ldif_text: &str) -> &Self {
        let tmp_ldif = self.dir.path().join("tmp.ldif");
        tokio::fs::write(&tmp_ldif, ldif_text).await.unwrap();
        self.add_ldif_file(tmp_ldif).await
    }

    pub async fn add_ldif_config(&self, ldif_text: &str) -> &Self {
        let tmp_ldif = self.dir.path().join("tmp.ldif");
        tokio::fs::write(&tmp_ldif, ldif_text).await.unwrap();
        self.add_ldif_file_binddn(tmp_ldif, "cn=config", "secret")
            .await;
        self
    }

    pub async fn add_ldif_file<P: AsRef<Path>>(&self, file: P) -> &Self {
        self.add_ldif_file_binddn(file, self.root_dn(), self.root_pw())
            .await;
        self
    }

    pub async fn add_ldif_file_binddn<P: AsRef<Path>>(
        &self,
        file: P,
        binddn: &str,
        password: &str,
    ) -> &Self {
        let file = file.as_ref();

        let output = Command::new("ldapadd")
            .args(["-x", "-D", binddn, "-w", password, "-H", self.url(), "-f"])
            .arg(file)
            .current_dir(&self.dir)
            .output()
            .await
            .expect("failed to execute ldapadd");

        if !output.status.success() {
            panic!(
                "ldapadd command exited with error {}, stdout: {}, stderr: {} on file {}",
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
            println!(
                "failed to kill slapd server: {}, pid: {:?}",
                e,
                self.server.id()
            );
        } else {
            println!("killed slapd server pid: {:?}", self.server.id());
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
            .add_system_ldif(0, "pmi.ldif")
            .add_ldif(
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
            .add_ldif_file(1, concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fry.ldif"))
            .run()
            .await;

        server
            .add_ldif(
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
