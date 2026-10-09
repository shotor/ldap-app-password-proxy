mod config;
mod hash;
mod session;
mod strip;
mod upstream;

use std::sync::Arc;

use anyhow::Context;
use tokio::net::TcpListener;
use tokio::sync::Semaphore;
use tracing::{error, info};
use tracing_subscriber::EnvFilter;

use crate::config::Config;
use crate::session::Session;
use crate::upstream::Upstream;

/// Argon2 checks running at once; each takes the hash's memory cost, 64 MiB for the extension's.
const ARGON2_CONCURRENCY: usize = 2;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
  tracing_subscriber::fmt()
    .json()
    .with_env_filter(EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")))
    .init();

  let config = Arc::new(Config::from_env()?);
  let upstream = Arc::new(Upstream::new(&config)?);
  let argon2 = Arc::new(Semaphore::new(ARGON2_CONCURRENCY));

  let listener = TcpListener::bind(&config.listen)
    .await
    .with_context(|| format!("listening on {}", config.listen))?;

  info!(
    listen = %config.listen,
    upstream = %config.upstream_host,
    attribute = %config.password_attribute,
    "ready"
  );

  loop {
    let (stream, peer) = listener.accept().await?;
    let session = Session::new(config.clone(), upstream.clone(), argon2.clone());

    tokio::spawn(async move {
      if let Err(err) = session.run(stream).await {
        error!(%peer, error = %err, "session ended with an error");
      }
    });
  }
}
