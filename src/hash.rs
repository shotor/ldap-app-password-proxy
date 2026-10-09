use std::str::FromStr;

use anyhow::{Context, bail, ensure};
use argon2::{Algorithm, Argon2, Params, Version};
use base64::Engine;
use base64::alphabet::STANDARD;
use base64::engine::general_purpose::GeneralPurpose;
use base64::engine::{DecodePaddingMode, GeneralPurposeConfig};
use subtle::ConstantTimeEq;

/// The most memory one check may take, in KiB; a hash asking for more is refused rather than
/// allowed to exhaust the sidecar.
pub const MAX_MEMORY_KIB: u32 = 1024 * 1024;

/// Unpadded standard base64 as PHC strings use it, tolerant of padding and trailing bits.
const PHC_BASE64: GeneralPurpose = GeneralPurpose::new(
  &STANDARD,
  GeneralPurposeConfig::new()
    .with_encode_padding(false)
    .with_decode_padding_mode(DecodePaddingMode::Indifferent)
    .with_decode_allow_trailing_bits(true),
);

/// An argon2id hash in the form the app passwords extension stores it:
/// `$argon2id$v=19$m=<kib>,t=<iterations>,p=<lanes>$<salt>$<hash>`.
///
/// Parsed by hand because the extension's 64-byte salt is longer than the `password-hash` crate's
/// PHC parser accepts.
pub struct Argon2idHash {
  params: Params,
  salt: Vec<u8>,
  hash: Vec<u8>,
}

impl Argon2idHash {
  /// Whether `password` hashes to the stored value, compared in constant time.
  pub fn verify(&self, password: &[u8]) -> bool {
    let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, self.params.clone());
    let mut computed = vec![0u8; self.hash.len()];

    if argon2
      .hash_password_into(password, &self.salt, &mut computed)
      .is_err()
    {
      return false;
    }

    computed.ct_eq(&self.hash).into()
  }
}

impl FromStr for Argon2idHash {
  type Err = anyhow::Error;

  fn from_str(value: &str) -> anyhow::Result<Self> {
    let mut parts = value.split('$');

    let (Some(""), Some(algorithm), Some(version), Some(params), Some(salt), Some(hash), None) = (
      parts.next(),
      parts.next(),
      parts.next(),
      parts.next(),
      parts.next(),
      parts.next(),
      parts.next(),
    ) else {
      bail!("not a PHC string with six fields");
    };

    ensure!(
      algorithm == "argon2id",
      "algorithm is {algorithm}, not argon2id"
    );
    ensure!(version == "v=19", "version is {version}, not v=19");

    let (memory, iterations, lanes) = parse_params(params)?;

    ensure!(
      memory <= MAX_MEMORY_KIB,
      "memory cost {memory} KiB is above the limit"
    );

    let salt = PHC_BASE64.decode(salt).context("salt is not base64")?;
    let hash = PHC_BASE64.decode(hash).context("hash is not base64")?;

    let params = Params::new(memory, iterations, lanes, Some(hash.len()))
      .map_err(|err| anyhow::anyhow!("parameters refused: {err}"))?;

    Ok(Self { params, salt, hash })
  }
}

/// The `m`, `t` and `p` values of a PHC parameter field, in any order, each exactly once.
fn parse_params(field: &str) -> anyhow::Result<(u32, u32, u32)> {
  let (mut memory, mut iterations, mut lanes) = (None, None, None);

  for pair in field.split(',') {
    let (key, value) = pair.split_once('=').context("parameter without a value")?;
    let value: u32 = value
      .parse()
      .with_context(|| format!("parameter {key} is not a number"))?;

    let slot = match key {
      "m" => &mut memory,
      "t" => &mut iterations,
      "p" => &mut lanes,
      _ => bail!("unknown parameter {key}"),
    };

    ensure!(slot.replace(value).is_none(), "parameter {key} given twice");
  }

  Ok((
    memory.context("no memory cost")?,
    iterations.context("no iteration count")?,
    lanes.context("no lane count")?,
  ))
}

#[cfg(test)]
#[path = "hash__test.rs"]
mod hash_test;
