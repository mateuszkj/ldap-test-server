use std::convert::AsRef;
use std::path::Path;
use std::{
    io::{BufRead, BufReader},
    net::{TcpStream, ToSocketAddrs},
    process::{Child, Command, Stdio},
    thread::sleep,
    time::Duration,
};
use url::Url;

use tempfile::{tempdir, TempDir};
use timeout_readwrite::TimeoutReader;

const INIT_LDIF: &str = include_str!("init.ldif");
const POSSIBLE_SCHEMA_DIR: &[&str] = &[
    "/etc/ldap/schema",
    "/usr/local/etc/openldap/schema",
    "/etc/openldap/schema/",
];

pub struct LdapServerBuilder {
    dir: TempDir,
    base_dn: String,
    root_dn: String,
    root_pw: String,
}

impl LdapServerBuilder {
    pub fn init(base_dn: &str) -> Self {
        LdapServerBuilder::init_with_config(base_dn, INIT_LDIF)
    }

    pub fn init_with_config(base_dn: &str, init_config: &str) -> Self {
        let root_dn = format!("cn=admin,{base_dn}");
        let root_pw = "secret".to_string();

        let schema_dir = find_slapd_schema_dir()
            .expect("no slapd schema directory found. Is openldap server installed?");
        let schema_dir = Url::from_file_path(schema_dir).unwrap();

        let init_ldif = init_config
            .replace("@SCHEMADIR@", schema_dir.as_ref())
            .replace("@BASEDN@", base_dn)
            .replace("@ROOTDN@", &root_dn)
            .replace("@ROOTPW@", &root_pw);

        let builder = LdapServerBuilder::init_empty(base_dn, root_dn, root_pw);
        builder.add_ldif(&init_ldif, 0)
    }

    pub fn init_empty(
        base_dn: impl Into<String>,
        root_dn: impl Into<String>,
        root_pw: impl Into<String>,
    ) -> Self {
        let dir = tempdir().unwrap();
        let base_dn = base_dn.into();
        let root_dn = root_dn.into();
        let root_pw = root_pw.into();

        Self {
            dir,
            base_dn,
            root_dn,
            root_pw,
        }
    }

    pub fn add_ldif(self, ldif_text: &str, database_number: u8) -> Self {
        let tmp_ldif = self.dir.path().join("tmp.ldif");
        std::fs::write(&tmp_ldif, ldif_text).unwrap();
        self.add_ldif_file(tmp_ldif, database_number)
    }

    pub fn add_ldif_file<P: AsRef<Path>>(self, file: P, database_number: u8) -> Self {
        let file = file.as_ref();

        let db_number = database_number.to_string();
        // load slapd configuration
        let output = Command::new("slapadd")
            .args(["-F", ".", "-n"])
            .arg(db_number)
            .arg("-l")
            .arg(file)
            .current_dir(&self.dir)
            .output()
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

        self
    }

    // Start LDAP server
    pub fn run(self) -> LdapServerConn {
        let host = "localhost".to_string();
        let port = portpicker::pick_unused_port().expect("no free tcp port to bind");
        let url = format!("ldap://{host}:{port}");

        // lauch slapd server
        let mut server = Command::new("slapd")
            .args(["-F", ".", "-d", "2048", "-h", &url])
            .stderr(Stdio::piped())
            .current_dir(&self.dir)
            .spawn()
            .unwrap();

        // wait unitl slapd server has started
        let stderr = server.stderr.take().unwrap();
        let timeouted = TimeoutReader::new(stderr, Duration::from_secs(5));
        let reader = BufReader::new(timeouted);

        let mut started = false;
        for line in reader.lines() {
            let line_str = line.unwrap();
            println!("{}", line_str);
            if line_str.ends_with("slapd starting") {
                started = true;
                break;
            }
        }

        if !started {
            server.kill().ok();
            panic!("Failed to start slapd server stderr");
        }

        // test if tcp port is open
        if !is_tcp_port_open(&host, port) {
            println!("tcp port {port} is not open yet, waiting...");
            sleep(Duration::from_secs(1));
        }

        if !is_tcp_port_open(&host, port) {
            server.kill().ok();
            panic!("Failed to start slapd server, port {port} not open");
        }

        println!("Started ldap server on {url}");

        LdapServerConn {
            url,
            host,
            port,
            dir: self.dir,
            base_dn: self.base_dn,
            root_dn: self.root_dn,
            root_pw: self.root_pw,
            server,
        }
    }
}
fn find_slapd_schema_dir() -> Option<&'static Path> {
    for dir in POSSIBLE_SCHEMA_DIR {
        let dir: &Path = dir.as_ref();
        if dir.is_dir() {
            return Some(dir);
        }
    }
    None
}

fn is_tcp_port_open(host: &str, port: u16) -> bool {
    let addr = (host, port).to_socket_addrs().unwrap().next().unwrap();
    TcpStream::connect_timeout(&addr, Duration::from_millis(500)).is_ok()
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

    pub fn add_ldif(&self, ldif_text: &str) -> &Self {
        let tmp_ldif = self.dir.path().join("tmp.ldif");
        std::fs::write(&tmp_ldif, ldif_text).unwrap();
        self.add_ldif_file(tmp_ldif)
    }

    pub fn add_ldif_config(&self, ldif_text: &str) -> &Self {
        let tmp_ldif = self.dir.path().join("tmp.ldif");
        std::fs::write(&tmp_ldif, ldif_text).unwrap();
        self.add_ldif_file_binddn(tmp_ldif, "cn=config", "secret");
        self
    }

    pub fn add_ldif_file<P: AsRef<Path>>(&self, file: P) -> &Self {
        self.add_ldif_file_binddn(file, self.root_dn(), self.root_pw());
        self
    }

    pub fn add_ldif_file_binddn<P: AsRef<Path>>(
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
        if let Err(e) = self.server.kill() {
            println!(
                "failed to kill slapd server: {}, pid: {}",
                e,
                self.server.id()
            );
        } else {
            println!("killed slapd server pid: {}", self.server.id());
        }
    }
}

#[cfg(test)]
mod tests {

    use super::*;

    #[test]
    fn run_slapd() {
        let server = LdapServerBuilder::init("dc=planetexpress,dc=com")
            .add_ldif(
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
                1,
            )
            .run();

        server.add_ldif(
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
uid: amy
userPassword:: e1NTSEF9d0p2OXMyWjltMGJTMFIxV1k3QjdCRWZEVVZPQzg2Y3BWL3VDMHc9PQ=
 =",
        );

        println!("server: {server:?}");
    }
}
