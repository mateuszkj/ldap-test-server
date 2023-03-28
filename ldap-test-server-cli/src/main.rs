use clap::{arg, Parser};
use ldap_test_server::LdapServerBuilder;
use std::ffi::OsStr;
use std::io;
use std::path::{Path, PathBuf};
use tokio::signal;
use tracing::level_filters::LevelFilter;
use tracing::{info, warn};
use tracing_subscriber::EnvFilter;

/// Simple program to greet a person
#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Args {
    /// Base DN
    #[arg(short, long, default_value = "dc=planetexpress,dc=com")]
    base_dn: String,

    /// Bind ldap server on address
    #[arg(long)]
    bind_addr: Option<String>,

    /// Port of ldap server
    #[arg(long)]
    port: Option<u16>,

    /// Directory of ldif files with schema which be installed in database 0
    #[arg(short, long)]
    schema_dir: Option<PathBuf>,

    /// Directory of ldif files with data which be installed in database 1
    #[arg(short, long)]
    data_dir: Option<PathBuf>,
}

#[tokio::main(flavor = "current_thread")]
async fn main() {
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::builder()
                .with_default_directive(LevelFilter::INFO.into())
                .from_env_lossy(),
        )
        .init();

    let args = Args::parse();
    info!("args: {args:?}");
    let base_dn = args.base_dn;

    let mut builder = LdapServerBuilder::new(&base_dn).add(
        1,
        &format!(
            "dn: {base_dn}
objectclass: dcObject
objectclass: organization
o: ldap-test-server-cli"
        ),
    );

    if let Some(bind_addr) = &args.bind_addr {
        builder = builder.bind_addr(bind_addr);
    }

    if let Some(port) = args.port {
        builder = builder.port(port);
    }

    let schema_files = if let Some(dir) = &args.schema_dir {
        list_ldif_files(dir)
            .await
            .expect("cannot list ldif files from schema_dir")
    } else {
        vec![]
    };

    for ldif in schema_files {
        info!("add schema file {}", ldif.display());
        builder = builder.add_file(0, ldif);
    }

    let data_files = if let Some(dir) = &args.data_dir {
        list_ldif_files(dir)
            .await
            .expect("cannot list ldif files from data_dir")
    } else {
        vec![]
    };

    for ldif in data_files {
        info!("add data file {}", ldif.display());
        builder = builder.add_file(1, ldif);
    }

    let server = builder.run().await;
    info!(
        "Server started on: {} in dir {}",
        server.url(),
        server.server_dir().display()
    );

    info!(
        "ldapsearch -x -H \"{}\" -D \"{}\" -w \"{}\" -b \"{}\" \"(objectClass=*)\"",
        server.url(),
        server.root_dn(),
        server.root_pw(),
        server.base_dn(),
    );

    info!("waiting for ctrl-c");
    signal::ctrl_c().await.expect("failed to listen for event");
}

async fn list_ldif_files<P: AsRef<Path>>(dir: P) -> io::Result<Vec<PathBuf>> {
    let mut entries = tokio::fs::read_dir(dir).await?;
    let mut ret = vec![];

    while let Some(entry) = entries.next_entry().await? {
        let path = entry.path();
        if path.extension() == Some(OsStr::new("ldif")) {
            ret.push(path)
        } else {
            warn!("Ignoring file {}", path.display());
        }
    }

    ret.sort();

    Ok(ret)
}
