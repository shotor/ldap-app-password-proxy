use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, bail};
use futures_util::{SinkExt, StreamExt};
use ldap3_proto::LdapCodec;
use ldap3_proto::proto::{
  LdapBindCred, LdapBindRequest, LdapDerefAliases, LdapFilter, LdapMsg, LdapOp, LdapResult,
  LdapResultCode, LdapSearchRequest, LdapSearchResultEntry, LdapSearchScope,
};
use rustls::RootCertStore;
use rustls_pki_types::pem::PemObject;
use rustls_pki_types::{CertificateDer, ServerName};
use tokio::net::TcpStream;
use tokio::time::timeout;
use tokio_rustls::TlsConnector;
use tokio_rustls::client::TlsStream;
use tokio_util::codec::Framed;

use crate::config::Config;

/// How long one exchange with the directory may take before the proxy gives up on it.
const UPSTREAM_TIMEOUT: Duration = Duration::from_secs(10);

/// The directory behind the proxy, reached over LDAPS and verified against the configured CA.
pub struct Upstream {
  connector: TlsConnector,
  address: (String, u16),
  server_name: ServerName<'static>,
}

impl Upstream {
  pub fn new(config: &Config) -> anyhow::Result<Self> {
    let mut roots = RootCertStore::empty();

    for certificate in CertificateDer::pem_file_iter(&config.upstream_ca_file)
      .with_context(|| format!("reading {}", config.upstream_ca_file.display()))?
    {
      roots.add(certificate?)?;
    }

    let tls = rustls::ClientConfig::builder_with_provider(Arc::new(
      rustls::crypto::ring::default_provider(),
    ))
    .with_safe_default_protocol_versions()?
    .with_root_certificates(roots)
    .with_no_client_auth();

    Ok(Self {
      connector: TlsConnector::from(Arc::new(tls)),
      address: (config.upstream_host.clone(), config.upstream_port),
      server_name: ServerName::try_from(config.upstream_host.clone())?,
    })
  }

  pub async fn connect(&self) -> anyhow::Result<Connection> {
    let open = async {
      let tcp = TcpStream::connect(&self.address).await?;
      let tls = self
        .connector
        .connect(self.server_name.clone(), tcp)
        .await?;

      anyhow::Ok(tls)
    };

    let tls = timeout(UPSTREAM_TIMEOUT, open)
      .await
      .context("connecting to the directory timed out")??;

    Ok(Connection {
      framed: Framed::new(tls, LdapCodec::default()),
      next_msgid: 1,
    })
  }
}

/// One LDAP connection to the directory.
pub struct Connection {
  framed: Framed<TlsStream<TcpStream>, LdapCodec>,
  next_msgid: i32,
}

impl Connection {
  pub async fn send(&mut self, msg: LdapMsg) -> anyhow::Result<()> {
    timeout(UPSTREAM_TIMEOUT, self.framed.send(msg))
      .await
      .context("writing to the directory timed out")??;

    Ok(())
  }

  pub async fn receive(&mut self) -> anyhow::Result<LdapMsg> {
    let received = timeout(UPSTREAM_TIMEOUT, self.framed.next())
      .await
      .context("waiting for the directory timed out")?;

    match received {
      Some(msg) => Ok(msg?),
      None => bail!("the directory closed the connection"),
    }
  }

  /// A simple bind on this connection, for the proxy's own lookups.
  pub async fn bind(&mut self, dn: &str, password: &str) -> anyhow::Result<LdapResult> {
    let msgid = self.msgid();

    self
      .send(LdapMsg {
        msgid,
        op: LdapOp::BindRequest(LdapBindRequest {
          dn: dn.to_string(),
          cred: LdapBindCred::Simple(password.to_string()),
        }),
        ctrl: vec![],
      })
      .await?;

    loop {
      let reply = self.receive().await?;

      if reply.msgid != msgid {
        continue;
      }

      match reply.op {
        LdapOp::BindResponse(response) => return Ok(response.res),
        other => bail!("the directory answered a bind with {other:?}"),
      }
    }
  }

  /// The entry at `dn` if it matches `filter`, with only `attributes`; `None` when it does not
  /// exist or does not match.
  pub async fn read_entry(
    &mut self,
    dn: &str,
    filter: LdapFilter,
    attributes: Vec<String>,
  ) -> anyhow::Result<Option<LdapSearchResultEntry>> {
    let msgid = self.msgid();

    self
      .send(LdapMsg {
        msgid,
        op: LdapOp::SearchRequest(LdapSearchRequest {
          base: dn.to_string(),
          scope: LdapSearchScope::Base,
          aliases: LdapDerefAliases::Never,
          sizelimit: 1,
          timelimit: 0,
          typesonly: false,
          filter,
          attrs: attributes,
        }),
        ctrl: vec![],
      })
      .await?;

    let mut found = None;

    loop {
      let reply = self.receive().await?;

      if reply.msgid != msgid {
        continue;
      }

      match reply.op {
        LdapOp::SearchResultEntry(entry) => found = Some(entry),
        LdapOp::SearchResultReference(_) => {}
        LdapOp::SearchResultDone(result) => {
          return match result.code {
            LdapResultCode::Success => Ok(found),
            LdapResultCode::NoSuchObject => Ok(None),
            code => bail!(
              "the directory refused the lookup: {code:?} {}",
              result.message
            ),
          };
        }
        other => bail!("the directory answered a search with {other:?}"),
      }
    }
  }

  fn msgid(&mut self) -> i32 {
    let msgid = self.next_msgid;

    self.next_msgid += 1;

    msgid
  }
}
