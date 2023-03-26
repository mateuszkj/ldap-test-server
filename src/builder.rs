use crate::LdapServerConn;
use rand::Rng;
use std::net::ToSocketAddrs;
use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::time::Duration;
use tempfile::tempdir;
use tokio::io::AsyncBufReadExt;
use tokio::net::TcpStream;
use tokio::process::Command;
use tokio::time::{sleep, timeout};
use tracing::debug;
use url::Url;

const INIT_LDIF: &str = include_str!("init.ldif");
const POSSIBLE_SCHEMA_DIR: &[&str] = &[
    "/etc/ldap/schema",
    "/usr/local/etc/openldap/schema",
    "/etc/openldap/schema/",
];

#[derive(Debug)]
enum LdapFile {
    SystemSchema(PathBuf),
    File { template: bool, file: PathBuf },
    Text { template: bool, content: String },
}

/// LDAP server builder
#[derive(Debug)]
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
        LdapServerBuilder::empty(base_dn, root_dn, root_pw).add_template(0, INIT_LDIF)
    }

    /// Add system LDIF from schema dir installed by slapd (usually in /etc/ldap/schema directory)
    ///
    /// # Examples
    ///
    /// ```
    /// use ldap_test_server::LdapServerBuilder;
    ///
    /// # #[tokio::main(flavor = "current_thread")]
    /// # async fn main() {
    /// let server = LdapServerBuilder::new("dc=planetexpress,dc=com")
    ///     .add_system_file(0, "collective.ldif")
    ///     .run().await;
    /// # }
    /// ```
    pub fn add_system_file<P: AsRef<Path>>(mut self, dbnum: u8, file: P) -> Self {
        self.includes
            .push((dbnum, LdapFile::SystemSchema(file.as_ref().to_path_buf())));
        self
    }

    /// Add LDIF file with text content
    ///
    /// # Examples
    ///
    /// ```
    /// use ldap_test_server::LdapServerBuilder;
    ///
    /// # #[tokio::main(flavor = "current_thread")]
    /// # async fn main() {
    /// let server = LdapServerBuilder::new("dc=planetexpress,dc=com")
    ///     .add(0, "dn: cn=user,cn=schema,cn=config
    /// objectClass: olcSchemaConfig
    /// cn: user
    /// olcAttributeTypes: ( 1.2.840.113556.4.221
    ///   NAME 'sAMAccountName'
    ///   SYNTAX '1.3.6.1.4.1.1466.115.121.1.15'
    ///   EQUALITY caseIgnoreMatch
    ///   SUBSTR caseIgnoreSubstringsMatch
    ///   SINGLE-VALUE )
    /// olcObjectClasses: ( 1.2.840.113556.1.5.9
    ///   NAME 'user'
    ///   SUP top
    ///   AUXILIARY
    ///   MAY ( sAMAccountName ))")
    ///     .run().await;
    /// # }
    /// ```
    pub fn add(mut self, dbnum: u8, content: &str) -> Self {
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
    pub fn add_file<P: AsRef<Path>>(mut self, dbnum: u8, file: P) -> Self {
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
    ///
    /// # Examples
    ///
    /// ```
    /// use ldap_test_server::{LdapServerConn, LdapServerBuilder};
    ///
    /// # #[tokio::main(flavor = "current_thread")]
    /// # async fn main() {
    /// let server: LdapServerConn = LdapServerBuilder::empty("dc=planetexpress,dc=com", "cn=admin,dc=planetexpress,dc=com", "secret")
    ///     .add_template(0, include_str!("init.ldif"))
    ///     .run().await;
    /// # }
    /// ```
    pub fn add_template(mut self, dbnum: u8, content: &str) -> Self {
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
    pub fn add_template_file<P: AsRef<Path>>(mut self, dbnum: u8, file: P) -> Self {
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

    /// Create database and run LDAP server
    ///
    /// # Examples
    ///
    /// ```
    /// use ldap_test_server::{LdapServerConn, LdapServerBuilder};
    ///
    /// # #[tokio::main(flavor = "current_thread")]
    /// # async fn main() {
    /// let server: LdapServerConn = LdapServerBuilder::new("dc=planetexpress,dc=com")
    ///     .run().await;
    /// # }
    /// ```
    pub async fn run(mut self) -> LdapServerConn {
        let schema_dir = find_slapd_schema_dir()
            .await
            .expect("no slapd schema directory found. Is openldap server installed?");
        let host = "127.0.0.1".to_string();
        let port = portpicker::pick_unused_port().unwrap_or_else(|| {
            let mut rng = rand::thread_rng();
            rng.gen_range(15000..55000)
        });

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
        let timeouted = timeout(Duration::from_secs(10), async {
            while let Some(line) = lines.next_line().await.unwrap() {
                debug!("slapd: {line}");
                if line.ends_with("slapd starting") {
                    return true;
                }
            }
            false
        })
        .await;

        if timeouted.is_err() || timeouted == Ok(false) {
            let _ = server.kill().await;
            panic!("Failed to start slapd server: timeout");
        }

        let timeouted = timeout(Duration::from_secs(2), async {
            while !is_tcp_port_open(&host, port).await {
                debug!("tcp port {port} is not open yet, waiting...");
                sleep(Duration::from_micros(100)).await;
            }
        })
        .await;

        if timeouted.is_err() {
            let _ = server.kill().await;
            panic!("Failed to start slapd server, port {port} not open");
        }

        debug!("Started ldap server on {url}");

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
