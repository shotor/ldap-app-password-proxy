use ldap3_proto::proto::LdapPartialAttribute;

use super::*;

fn attribute(name: &str) -> LdapPartialAttribute {
  LdapPartialAttribute {
    atype: name.to_string(),
    vals: vec![b"value".to_vec()],
  }
}

#[test]
fn hides_every_password_attribute() {
  for name in [
    "userPassword",
    "chatPassword",
    "mediaPassword",
    "emailPassword",
    "mediaPasswordCreated",
    "USERPASSWORD",
    "userPassword;binary",
  ] {
    assert!(is_hidden(name), "{name} passed");
  }
}

#[test]
fn keeps_ordinary_attributes() {
  for name in [
    "uid",
    "mail",
    "memberOf",
    "accountEnabled",
    "passwordExpirationTime",
  ] {
    assert!(!is_hidden(name), "{name} hidden");
  }
}

#[test]
fn strips_hidden_attributes_from_an_entry() {
  let entry = LdapSearchResultEntry {
    dn: "uid=alice,ou=People,dc=example,dc=org".to_string(),
    attributes: vec![
      attribute("uid"),
      attribute("mediaPassword"),
      attribute("mail"),
    ],
  };

  let names: Vec<_> = strip(entry)
    .attributes
    .into_iter()
    .map(|a| a.atype)
    .collect();

  assert_eq!(names, ["uid", "mail"]);
}
