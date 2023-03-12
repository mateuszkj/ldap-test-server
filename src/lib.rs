use std::{
    io::{BufRead, BufReader},
    net::{TcpStream, ToSocketAddrs},
    process::{Child, Command, Stdio},
    thread::sleep,
    time::Duration,
};

use tempfile::{tempdir, TempDir};
use timeout_readwrite::TimeoutReader;

const SLAPD_INIT_LDIF: &str = include_str!("slapd.init.ldif");

pub struct LdapServerBuilder {
    base_dn: String,
    root_dn: Option<String>,
    root_pw: Option<String>,
}

impl LdapServerBuilder {
    pub fn new(base_dn: &str) -> Self {
        Self {
            base_dn: base_dn.to_string(),
            root_dn: None,
            root_pw: None,
        }
    }

    // Start LDAP server
    pub fn run(self) -> LdapServerConn {
        let host = "localhost".to_string();
        let port = portpicker::pick_unused_port().expect("no free tcp port to bind");
        let dir = tempdir().unwrap();
        let url = format!("ldap://{host}:{port}");

        let base_dn = self.base_dn;
        let root_dn = self
            .root_dn
            .unwrap_or_else(|| format!("cn=admin,{base_dn}"));
        let root_pw = self.root_pw.unwrap_or_else(|| "secret".to_string());

        let slpad_init = SLAPD_INIT_LDIF
            .replace("@BASEDN@", &base_dn)
            .replace("@ROOTDN@", &root_dn)
            .replace("@ROOTPW@", &root_pw);

        let slapd_init_file = dir.path().join("slapd.init.ldif");
        std::fs::write(&slapd_init_file, &slpad_init).unwrap();

        // load slapd configuration
        let output = Command::new("slapadd")
            .args(["-F", ".", "-n", "0", "-l", "slapd.init.ldif"])
            .current_dir(&dir)
            .output()
            .expect("failed to execute slapadd");

        if !output.status.success() {
            panic!("slapadd command exited with error {}, stdout: {}, stderr: {}, slapd.init.ldif: {slpad_init}",
            output.status,
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr));
        }

        // lauch slapd server
        let mut server = Command::new("slapd")
            .args(["-F", ".", "-d", "2048", "-h", &url])
            .stderr(Stdio::piped())
            .current_dir(&dir)
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
            println!("tcp port {port} is not open yet");
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
            dir,
            base_dn,
            root_dn,
            root_pw,
            server,
        }
    }
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

    use super::LdapServerBuilder;

    #[test]
    fn run_slapd() {
        let server = LdapServerBuilder::new("dc=kondej,dc=net").run();
        println!("server: {server:?}");
    }
}
