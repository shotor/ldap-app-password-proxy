use ldap3_proto::parse_ldap_filter_str;
use ldap3_proto::proto::{
  LdapCompareRequest, LdapExtendedRequest, LdapPartialAttribute, SaslCredentials,
};

use super::*;

fn config() -> Config {
  Config {
    listen: "127.0.0.1:3389".to_string(),
    upstream_host: "ldap.example.org".to_string(),
    upstream_port: 3636,
    upstream_ca_file: "/etc/ssl/directory/ca.crt".into(),
    service_dn: "uid=svc-app,ou=People,dc=example,dc=org".to_string(),
    service_password: "secret".to_string(),
    password_attribute: "appPassword".to_string(),
    user_filter: parse_ldap_filter_str("(objectClass=person)").unwrap(),
  }
}

fn simple(dn: &str, password: &str) -> LdapBindRequest {
  LdapBindRequest {
    dn: dn.to_string(),
    cred: LdapBindCred::Simple(password.to_string()),
  }
}

#[test]
fn the_service_account_is_recognised_whatever_its_case_and_spacing() {
  let config = config();

  for dn in [
    "uid=svc-app,ou=People,dc=example,dc=org",
    "UID=svc-app, ou=people, DC=example, dc=ORG",
  ] {
    assert_eq!(
      classify_bind(&config, &simple(dn, "secret")),
      BindKind::Service,
      "{dn}"
    );
  }
}

#[test]
fn anyone_else_is_a_user() {
  let bind = simple("uid=alice,ou=People,dc=example,dc=org", "app password");

  assert_eq!(classify_bind(&config(), &bind), BindKind::User);
}

#[test]
fn anonymous_and_empty_password_binds_are_refused() {
  let config = config();

  for bind in [
    simple("", ""),
    simple("", "password"),
    simple("uid=alice,ou=People,dc=example,dc=org", ""),
    simple("uid=svc-app,ou=People,dc=example,dc=org", ""),
  ] {
    assert!(
      matches!(classify_bind(&config, &bind), BindKind::Refused(..)),
      "{:?}",
      bind.dn
    );
  }
}

#[test]
fn sasl_binds_are_refused() {
  let bind = LdapBindRequest {
    dn: String::new(),
    cred: LdapBindCred::SASL(SaslCredentials {
      mechanism: "EXTERNAL".to_string(),
      credentials: vec![],
    }),
  };

  assert_eq!(
    classify_bind(&config(), &bind),
    BindKind::Refused(LdapResultCode::AuthMethodNotSupported, "simple binds only")
  );
}

#[test]
fn finds_the_stored_hash_whatever_the_attributes_case() {
  let entry = LdapSearchResultEntry {
    dn: "uid=alice,ou=People,dc=example,dc=org".to_string(),
    attributes: vec![LdapPartialAttribute {
      atype: "apppassword".to_string(),
      vals: vec![b"$argon2id$v=19$m=64,t=1,p=1$c2FsdA$aGFzaA".to_vec()],
    }],
  };

  assert!(stored_hash(Some(&entry), "appPassword").is_some());
  assert!(stored_hash(Some(&entry), "otherPassword").is_none());
  assert!(stored_hash(None, "appPassword").is_none());
}

#[test]
fn writes_and_compares_are_refused() {
  let compare = LdapMsg {
    msgid: 4,
    op: LdapOp::CompareRequest(LdapCompareRequest {
      dn: "uid=alice,ou=People,dc=example,dc=org".to_string(),
      atype: "appPassword".to_string(),
      val: b"guess".to_vec(),
    }),
    ctrl: vec![],
  };

  let password_modify = LdapMsg {
    msgid: 5,
    op: LdapOp::ExtendedRequest(LdapExtendedRequest {
      name: "1.3.6.1.4.1.4203.1.11.1".to_string(),
      value: None,
    }),
    ctrl: vec![],
  };

  for msg in [
    compare,
    password_modify,
    LdapMsg {
      msgid: 6,
      op: LdapOp::DelRequest("uid=alice".to_string()),
      ctrl: vec![],
    },
  ] {
    let reply = refusal(&msg).expect("no answer");

    assert_eq!(reply.msgid, msg.msgid);

    let code = match reply.op {
      LdapOp::CompareResult(res) | LdapOp::DelResponse(res) => res.code,
      LdapOp::ExtendedResponse(response) => response.res.code,
      other => panic!("unexpected answer {other:?}"),
    };

    assert_eq!(code, LdapResultCode::UnwillingToPerform);
  }
}

#[test]
fn a_failed_guess_costs_at_least_a_second() {
  assert!(FAILURE_DELAY >= Duration::from_secs(1));
}
