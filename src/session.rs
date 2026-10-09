use std::sync::Arc;
use std::time::Duration;

use anyhow::Context;
use futures_util::{SinkExt, StreamExt};
use ldap3_proto::LdapCodec;
use ldap3_proto::proto::{
  LdapBindCred, LdapBindRequest, LdapBindResponse, LdapExtendedResponse, LdapMsg, LdapOp,
  LdapResult, LdapResultCode, LdapSearchResultEntry,
};
use tokio::net::TcpStream;
use tokio::sync::Semaphore;
use tokio::time::sleep;
use tokio_util::codec::Framed;
use tracing::{error, info, warn};

use crate::config::Config;
use crate::hash::Argon2idHash;
use crate::strip::strip;
use crate::upstream::{Connection, Upstream};

/// How long a refused user bind waits before its answer, so guessing costs time.
pub const FAILURE_DELAY: Duration = Duration::from_secs(1);

type Client = Framed<TcpStream, LdapCodec>;

/// Who the client is bound as. Only the service account gets a connection to the directory; a user
/// bind is answered by the proxy alone and leaves the client unable to search.
enum State {
  Anonymous,
  Service(Box<Connection>),
  User,
}

/// What a bind request asks for, decided before anything is sent to the directory.
#[derive(Debug, PartialEq)]
pub enum BindKind {
  Service,
  User,
  Refused(LdapResultCode, &'static str),
}

pub struct Session {
  config: Arc<Config>,
  upstream: Arc<Upstream>,
  argon2: Arc<Semaphore>,
  state: State,
}

impl Session {
  pub fn new(config: Arc<Config>, upstream: Arc<Upstream>, argon2: Arc<Semaphore>) -> Self {
    Self {
      config,
      upstream,
      argon2,
      state: State::Anonymous,
    }
  }

  pub async fn run(mut self, stream: TcpStream) -> anyhow::Result<()> {
    let mut client = Framed::new(stream, LdapCodec::default());

    while let Some(msg) = client.next().await {
      let msg = msg.context("reading the client")?;

      match msg.op {
        LdapOp::UnbindRequest => break,
        LdapOp::AbandonRequest(_) => {}
        LdapOp::BindRequest(ref bind) => {
          let reply = self.bind(msg.msgid, bind).await;

          client.send(reply).await?;
        }
        LdapOp::SearchRequest(_) => self.search(msg, &mut client).await?,
        _ => {
          if let Some(reply) = refusal(&msg) {
            client.send(reply).await?;
          }
        }
      }
    }

    Ok(())
  }

  async fn bind(&mut self, msgid: i32, bind: &LdapBindRequest) -> LdapMsg {
    // A bind replaces whatever the connection was bound as, also when it fails.
    self.state = State::Anonymous;

    match classify_bind(&self.config, bind) {
      BindKind::Refused(code, message) => bind_response(msgid, code, message),
      BindKind::Service => self.bind_service(msgid, bind).await,
      BindKind::User => self.bind_user(msgid, bind).await,
    }
  }

  /// The service account's bind goes to the directory as it is, and the connection stays for its
  /// searches.
  async fn bind_service(&mut self, msgid: i32, bind: &LdapBindRequest) -> LdapMsg {
    let attempt = async {
      let mut connection = self.upstream.connect().await?;

      connection
        .send(LdapMsg {
          msgid,
          op: LdapOp::BindRequest(bind.clone()),
          ctrl: vec![],
        })
        .await?;

      loop {
        let reply = connection.receive().await?;

        if reply.msgid == msgid {
          return anyhow::Ok((reply, connection));
        }
      }
    };

    match attempt.await {
      Ok((reply, connection)) => {
        if is_bind_success(&reply) {
          self.state = State::Service(Box::new(connection));
        }

        reply
      }
      Err(err) => {
        error!(error = %err, "service bind could not reach the directory");
        bind_response(
          msgid,
          LdapResultCode::Unavailable,
          "the directory is unreachable",
        )
      }
    }
  }

  /// A user's bind is never forwarded: the proxy checks the typed password against the app
  /// password's hash and answers itself.
  async fn bind_user(&mut self, msgid: i32, bind: &LdapBindRequest) -> LdapMsg {
    let LdapBindCred::Simple(password) = &bind.cred else {
      return bind_response(
        msgid,
        LdapResultCode::AuthMethodNotSupported,
        "simple binds only",
      );
    };

    let verdict = {
      let _permit = self.argon2.acquire().await;

      self.check_user(&bind.dn, password).await
    };

    match verdict {
      Ok(true) => {
        info!(dn = %bind.dn, "user bind accepted");
        self.state = State::User;

        bind_response(msgid, LdapResultCode::Success, "")
      }
      Ok(false) => {
        warn!(dn = %bind.dn, "user bind refused");
        sleep(FAILURE_DELAY).await;

        bind_response(msgid, LdapResultCode::InvalidCredentials, "")
      }
      Err(err) => {
        error!(dn = %bind.dn, error = %err, "user bind could not be checked");

        bind_response(
          msgid,
          LdapResultCode::Unavailable,
          "the directory is unreachable",
        )
      }
    }
  }

  async fn check_user(&self, dn: &str, password: &str) -> anyhow::Result<bool> {
    let config = &self.config;
    let mut connection = self.upstream.connect().await?;
    let bound = connection
      .bind(&config.service_dn, &config.service_password)
      .await?;

    anyhow::ensure!(
      bound.code == LdapResultCode::Success,
      "the service account's bind was refused: {:?}",
      bound.code
    );

    let entry = connection
      .read_entry(
        dn,
        config.user_filter.clone(),
        vec![config.password_attribute.clone()],
      )
      .await?;

    let Some(stored) = stored_hash(entry.as_ref(), &config.password_attribute) else {
      return Ok(false);
    };

    let hash: Argon2idHash = match stored.parse() {
      Ok(hash) => hash,
      Err(err) => {
        warn!(%dn, error = %err, "stored app password is not an argon2id hash");
        return Ok(false);
      }
    };

    let password = password.as_bytes().to_vec();

    Ok(tokio::task::spawn_blocking(move || hash.verify(&password)).await?)
  }

  /// Searches pass to the directory only for the service account, every hidden attribute removed
  /// from the entries that come back.
  async fn search(&mut self, msg: LdapMsg, client: &mut Client) -> anyhow::Result<()> {
    let msgid = msg.msgid;

    let State::Service(connection) = &mut self.state else {
      let done = LdapResult {
        code: LdapResultCode::InsufficentAccessRights,
        matcheddn: String::new(),
        message: "bind as the service account to search".to_string(),
        referral: vec![],
      };

      client
        .send(LdapMsg {
          msgid,
          op: LdapOp::SearchResultDone(done),
          ctrl: vec![],
        })
        .await?;

      return Ok(());
    };

    connection.send(msg).await?;

    loop {
      let mut reply = connection.receive().await?;

      if reply.msgid != msgid {
        continue;
      }

      let done = matches!(reply.op, LdapOp::SearchResultDone(_));

      if let LdapOp::SearchResultEntry(entry) = reply.op {
        reply.op = LdapOp::SearchResultEntry(strip(entry));
      }

      client.send(reply).await?;

      if done {
        return Ok(());
      }
    }
  }
}

/// Which kind of bind this is: the configured service account, a user, or nothing the proxy
/// accepts. Anonymous and empty-password binds would succeed unauthenticated in LDAP, so they are
/// refused outright.
pub fn classify_bind(config: &Config, bind: &LdapBindRequest) -> BindKind {
  let LdapBindCred::Simple(password) = &bind.cred else {
    return BindKind::Refused(LdapResultCode::AuthMethodNotSupported, "simple binds only");
  };

  if bind.dn.trim().is_empty() || password.is_empty() {
    return BindKind::Refused(LdapResultCode::InvalidCredentials, "");
  }
  if same_dn(&bind.dn, &config.service_dn) {
    return BindKind::Service;
  }

  BindKind::User
}

/// The app password's hash in a looked-up entry, if the entry exists and carries one.
pub fn stored_hash(entry: Option<&LdapSearchResultEntry>, attribute: &str) -> Option<String> {
  entry?
    .attributes
    .iter()
    .find(|candidate| candidate.atype.eq_ignore_ascii_case(attribute))?
    .vals
    .first()
    .and_then(|value| String::from_utf8(value.clone()).ok())
}

/// The answer to an operation the proxy never performs, or `None` for one that gets no answer.
pub fn refusal(msg: &LdapMsg) -> Option<LdapMsg> {
  let res = LdapResult {
    code: LdapResultCode::UnwillingToPerform,
    matcheddn: String::new(),
    message: "this proxy only binds and searches".to_string(),
    referral: vec![],
  };

  let op = match &msg.op {
    LdapOp::ModifyRequest(_) => LdapOp::ModifyResponse(res),
    LdapOp::AddRequest(_) => LdapOp::AddResponse(res),
    LdapOp::DelRequest(_) => LdapOp::DelResponse(res),
    LdapOp::ModifyDNRequest(_) => LdapOp::ModifyDNResponse(res),
    LdapOp::CompareRequest(_) => LdapOp::CompareResult(res),
    LdapOp::ExtendedRequest(_) => LdapOp::ExtendedResponse(LdapExtendedResponse {
      res,
      name: None,
      value: None,
    }),
    _ => return None,
  };

  Some(LdapMsg {
    msgid: msg.msgid,
    op,
    ctrl: vec![],
  })
}

fn same_dn(left: &str, right: &str) -> bool {
  let normalize = |dn: &str| {
    dn.split(',')
      .map(|part| part.trim().to_ascii_lowercase())
      .collect::<Vec<_>>()
  };

  normalize(left) == normalize(right)
}

fn is_bind_success(msg: &LdapMsg) -> bool {
  matches!(&msg.op, LdapOp::BindResponse(response) if response.res.code == LdapResultCode::Success)
}

fn bind_response(msgid: i32, code: LdapResultCode, message: &str) -> LdapMsg {
  LdapMsg {
    msgid,
    op: LdapOp::BindResponse(LdapBindResponse {
      res: LdapResult {
        code,
        matcheddn: String::new(),
        message: message.to_string(),
        referral: vec![],
      },
      saslcreds: None,
    }),
    ctrl: vec![],
  }
}

#[cfg(test)]
#[path = "session__test.rs"]
mod session_test;
