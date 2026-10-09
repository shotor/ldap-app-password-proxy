use std::collections::HashMap;

use super::*;

fn password_file(name: &str, content: &str) -> String {
  let path = std::env::temp_dir().join(format!("lapp-{}-{name}", std::process::id()));

  fs::write(&path, content).unwrap();

  path.to_string_lossy().into_owned()
}

fn lookup(vars: HashMap<&'static str, String>) -> impl Fn(&str) -> Option<String> {
  move |name| vars.get(name).cloned()
}

fn minimal(password_file: String) -> HashMap<&'static str, String> {
  HashMap::from([
    ("LAPP_UPSTREAM_HOST", "ldap.example.org".to_string()),
    (
      "LAPP_UPSTREAM_CA_FILE",
      "/etc/ssl/directory/ca.crt".to_string(),
    ),
    (
      "LAPP_SERVICE_DN",
      "uid=svc-app,ou=People,dc=example,dc=org".to_string(),
    ),
    ("LAPP_SECRET_SERVICE_PASSWORD_FILE", password_file),
    ("LAPP_PASSWORD_ATTRIBUTE", "appPassword".to_string()),
    (
      "LAPP_USER_FILTER",
      "(&(objectClass=person)(memberOf=\"cn=user,ou=app,ou=Groups,dc=example,dc=org\"))"
        .to_string(),
    ),
  ])
}

#[test]
fn reads_the_settings_with_their_defaults() {
  let config = Config::from_lookup(lookup(minimal(password_file("defaults", "secret\n")))).unwrap();

  assert_eq!(config.listen, "127.0.0.1:3389");
  assert_eq!(config.upstream_port, 636);
  assert_eq!(config.password_attribute, "appPassword");
  assert!(matches!(config.user_filter, LdapFilter::And(_)));
}

#[test]
fn trims_only_the_password_files_line_ending() {
  let config =
    Config::from_lookup(lookup(minimal(password_file("trim", " pass word \r\n")))).unwrap();

  assert_eq!(config.service_password, " pass word ");
}

#[test]
fn refuses_a_missing_setting() {
  let mut vars = minimal(password_file("missing", "secret"));

  vars.remove("LAPP_PASSWORD_ATTRIBUTE");

  assert!(Config::from_lookup(lookup(vars)).is_err());
}

#[test]
fn a_quoted_dn_value_reaches_the_directory_without_its_quotes() {
  let config = Config::from_lookup(lookup(minimal(password_file("quoted", "secret")))).unwrap();

  let LdapFilter::And(parts) = config.user_filter else {
    panic!("not an and filter");
  };

  assert!(parts.contains(&LdapFilter::Equality(
    "memberOf".to_string(),
    "cn=user,ou=app,ou=Groups,dc=example,dc=org".to_string()
  )));
}

#[test]
fn refuses_a_filter_that_does_not_parse() {
  let mut vars = minimal(password_file("filter", "secret"));

  vars.insert("LAPP_USER_FILTER", "(&(objectClass=person)".to_string());

  assert!(Config::from_lookup(lookup(vars)).is_err());
}

#[test]
fn takes_the_password_from_the_environment_instead_of_a_file() {
  let mut vars = minimal(password_file("unused", "secret"));

  vars.remove("LAPP_SECRET_SERVICE_PASSWORD_FILE");
  vars.insert(
    "LAPP_SECRET_SERVICE_PASSWORD",
    "from the environment".to_string(),
  );

  let config = Config::from_lookup(lookup(vars)).unwrap();

  assert_eq!(config.service_password, "from the environment");
}

#[test]
fn refuses_the_password_from_both_places() {
  let mut vars = minimal(password_file("both", "secret"));

  vars.insert(
    "LAPP_SECRET_SERVICE_PASSWORD",
    "from the environment".to_string(),
  );

  assert!(Config::from_lookup(lookup(vars)).is_err());
}

#[test]
fn refuses_a_missing_password() {
  let mut vars = minimal(password_file("none", "secret"));

  vars.remove("LAPP_SECRET_SERVICE_PASSWORD_FILE");

  assert!(Config::from_lookup(lookup(vars)).is_err());
}
