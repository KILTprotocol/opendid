use serde::de::Error;
use serde::Deserialize;
use serde::{Deserializer, Serializer};

/// Serialize and deserialize `0x` prefixed hex strings to and from Vec<u8>.
pub mod prefixed_hex {

    use super::*;

    pub fn deserialize<'de, D>(deserializer: D) -> Result<Vec<u8>, D::Error>
    where
        D: Deserializer<'de>,
    {
        let s: &str = Deserialize::deserialize(deserializer)?;
        hex::decode(s.trim_start_matches("0x")).map_err(Error::custom)
    }

    pub fn serialize<S>(value: &Vec<u8>, s: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let hex = hex::encode(value);
        s.serialize_str(&format!("0x{}", hex))
    }
}

/// Serialize and deserialize `0x` prefixed hex strings to and from Vec<u8>.
pub mod hex_nonce {
    use sodiumoxide::crypto::box_::Nonce;

    use super::*;

    pub fn deserialize<'de, D>(deserializer: D) -> Result<Nonce, D::Error>
    where
        D: Deserializer<'de>,
    {
        let s: &str = Deserialize::deserialize(deserializer)?;
        let bytes = hex::decode(s.trim_start_matches("0x")).map_err(Error::custom)?;
        Nonce::from_slice(&bytes).ok_or_else(|| Error::custom("invalid nonce length"))
    }

    pub fn serialize<S>(value: &Nonce, s: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let hex = hex::encode(value);
        s.serialize_str(&format!("0x{}", hex))
    }
}
