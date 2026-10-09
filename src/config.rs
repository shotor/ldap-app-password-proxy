use std::fs;
use std::path::PathBuf;

use anyhow::{Context, anyhow, bail};
use ldap3_proto::parse_ldap_filter_str;
use ldap3_proto::proto::LdapFilter;

/// The proxy's settings, all from `LAPP_*` environment variables.
///
/// The service account's password is either the value of `LAPP_SECRET_SERVICE_PASSWORD` or the
/// content of the file `LAPP_SECRET_SERVICE_PASSWORD_FILE` names, never both.
///
/// `LAPP_USER_FILTER` is everything a user's entry must match to log in, an enabled flag included
/// when the directory has one. It is parsed by `ldap3_proto`, which stops at an `=` inside a value:
/// a DN value is written in double quotes, `(memberOf="cn=users,ou=Groups,dc=example,dc=org")`,
/// and reaches the directory without them.
pub struct Config {
  pub listen: String,
  pub upstream_host: String,
  pub upstream_port: u16,
  pub upstream_ca_file: PathBuf,
  pub service_dn: String,
  pub service_password: String,
  pub password_attribute: String,
  pub user_filter: LdapFilter,
}

impl Config {
  pub fn from_env() -> anyhow::Result<Self> {
    Self::from_lookup(|name| std::env::var(name).ok())
  }

  pub fn from_lookup(lookup: impl Fn(&str) -> Option<String>) -> anyhow::Result<Self> {
    let required = |name: &str| {
      lookup(name)
        .filter(|v| !v.is_empty())
        .context(format!("{name} is not set"))
    };
    let optional = |name: &str, default: &str| lookup(name).unwrap_or_else(|| default.to_string());

    let service_password = secret(&lookup, "LAPP_SECRET_SERVICE_PASSWORD")?;

    let user_filter = required("LAPP_USER_FILTER")?;

    let user_filter = parse_ldap_filter_str(&user_filter)
      .map_err(|err| anyhow!("LAPP_USER_FILTER is not an LDAP filter: {err}"))?;

    let upstream_port = optional("LAPP_UPSTREAM_PORT", "636")
      .parse()
      .context("LAPP_UPSTREAM_PORT is not a port")?;

    Ok(Self {
      listen: optional("LAPP_LISTEN", "127.0.0.1:3389"),
      upstream_host: required("LAPP_UPSTREAM_HOST")?,
      upstream_port,
      upstream_ca_file: required("LAPP_UPSTREAM_CA_FILE")?.into(),
      service_dn: required("LAPP_SERVICE_DN")?,
      service_password,
      password_attribute: required("LAPP_PASSWORD_ATTRIBUTE")?,
      user_filter,
    })
  }
}

/// A secret from `<name>` itself or from the file `<name>_FILE` names, exactly one of them; a file's
/// final line ending is not part of the secret.
fn secret(lookup: &impl Fn(&str) -> Option<String>, name: &str) -> anyhow::Result<String> {
  let file_name = format!("{name}_FILE");
  let value = lookup(name).filter(|v| !v.is_empty());
  let file = lookup(&file_name).filter(|v| !v.is_empty());

  match (value, file) {
    (Some(_), Some(_)) => bail!("{name} and {file_name} are both set"),
    (Some(value), None) => Ok(value),
    (None, Some(path)) => {
      let content = fs::read_to_string(&path).with_context(|| format!("reading {path}"))?;

      Ok(content.trim_end_matches(['\r', '\n']).to_string())
    }
    (None, None) => bail!("neither {name} nor {file_name} is set"),
  }
}

#[cfg(test)]
#[path = "config__test.rs"]
mod config_test;
