use super::*;

/// The extension's shape, a 64-byte salt and a 64-byte hash, with a cost small enough for tests.
fn encode(password: &[u8], memory: u32, iterations: u32) -> String {
  let salt = [7u8; 64];
  let params = Params::new(memory, iterations, 1, Some(64)).unwrap();
  let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
  let mut hash = [0u8; 64];

  argon2
    .hash_password_into(password, &salt, &mut hash)
    .unwrap();

  format!(
    "$argon2id$v=19$m={memory},t={iterations},p=1${}${}",
    PHC_BASE64.encode(salt),
    PHC_BASE64.encode(hash)
  )
}

#[test]
fn accepts_the_right_password() {
  let stored: Argon2idHash = encode(b"correct horse", 64, 1).parse().unwrap();

  assert!(stored.verify(b"correct horse"));
}

#[test]
fn refuses_a_wrong_password() {
  let stored: Argon2idHash = encode(b"correct horse", 64, 1).parse().unwrap();

  assert!(!stored.verify(b"correct horsf"));
  assert!(!stored.verify(b""));
}

#[test]
fn reads_parameters_in_any_order() {
  let stored = encode(b"pw", 64, 2).replace("m=64,t=2,p=1", "p=1,t=2,m=64");
  let stored: Argon2idHash = stored.parse().unwrap();

  assert!(stored.verify(b"pw"));
}

#[test]
fn verifies_the_extensions_own_parameters() {
  let stored: Argon2idHash = encode(b"app password", 65536, 5).parse().unwrap();

  assert!(stored.verify(b"app password"));
}

#[test]
fn refuses_other_argon2_variants() {
  let stored = encode(b"pw", 64, 1);

  assert!(
    stored
      .replace("$argon2id$", "$argon2i$")
      .parse::<Argon2idHash>()
      .is_err()
  );
  assert!(
    stored
      .replace("$argon2id$", "$argon2d$")
      .parse::<Argon2idHash>()
      .is_err()
  );
}

#[test]
fn refuses_other_versions() {
  let stored = encode(b"pw", 64, 1).replace("$v=19$", "$v=16$");

  assert!(stored.parse::<Argon2idHash>().is_err());
}

#[test]
fn refuses_a_memory_cost_above_the_limit() {
  let stored = encode(b"pw", 64, 1).replace("m=64,", &format!("m={},", MAX_MEMORY_KIB + 1));

  assert!(stored.parse::<Argon2idHash>().is_err());
}

// the limit may never refuse the extension's own cost of 64 MiB; checked when the tests compile
const _: () = assert!(MAX_MEMORY_KIB >= 65536);

#[test]
fn refuses_malformed_strings() {
  let stored = encode(b"pw", 64, 1);

  for bad in [
    "",
    "argon2id",
    "{ARGON2ID}$argon2id$v=19$m=64,t=1,p=1$c2FsdHNhbHQ$aGFzaA",
    "$argon2id$v=19$m=64,t=1$c2FsdHNhbHQ$aGFzaA",
    "$argon2id$v=19$m=64,t=1,p=1,m=64$c2FsdHNhbHQ$aGFzaA",
    "$argon2id$v=19$m=64,t=1,p=1,x=1$c2FsdHNhbHQ$aGFzaA",
    "$argon2id$v=19$m=64,t=1,p=1$not base64!$aGFzaA",
    &format!("{stored}$extra"),
  ] {
    assert!(bad.parse::<Argon2idHash>().is_err(), "accepted {bad:?}");
  }
}
