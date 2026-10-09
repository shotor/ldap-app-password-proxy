use ldap3_proto::proto::LdapSearchResultEntry;

/// Whether an attribute holds a password, a password hash or its creation date, which never leave
/// the proxy whatever the directory's rules allow.
pub fn is_hidden(attribute: &str) -> bool {
  let attribute = attribute.to_ascii_lowercase();
  let attribute = attribute.split(';').next().unwrap_or_default();

  attribute.ends_with("password") || attribute.ends_with("passwordcreated")
}

/// The entry without its hidden attributes.
pub fn strip(mut entry: LdapSearchResultEntry) -> LdapSearchResultEntry {
  entry
    .attributes
    .retain(|attribute| !is_hidden(&attribute.atype));
  entry
}

#[cfg(test)]
#[path = "strip__test.rs"]
mod strip_test;
