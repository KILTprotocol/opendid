use actix_web::cookie::Key;
use hex::FromHexError;
use serde::{Deserialize, Serialize};

use crate::jwt::TokenBuilder;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Config {
    pub host: String,
    pub port: u16,
    #[serde(rename = "sessionKey")]
    pub session_key: String,
    #[serde(rename = "keyUri")]
    pub key_uri: String,
    #[serde(rename = "naclPublicKey")]
    pub nacl_public_key: String,
    #[serde(rename = "naclSecretKey")]
    pub nacl_secret_key: String,
    #[serde(rename = "credentialRequirements")]
    pub credential_requirements: Vec<CredentialRequirement>,
    #[serde(rename = "tokenIssuer")]
    pub token_issuer: String,
    #[serde(rename = "accessTokenLifetime")]
    pub access_token_lifetime: i64,
    #[serde(rename = "accessTokenAudience")]
    pub access_token_audience: String,
    #[serde(rename = "refreshTokenLifetime")]
    pub refresh_token_lifetime: i64,
    #[serde(rename = "refreshTokenAudience")]
    pub refresh_token_audience: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CredentialRequirement {
    #[serde(rename = "cTypeHash")]
    pub ctype_hash: String,
    #[serde(rename = "trustedAttesters")]
    pub trusted_attesters: Vec<String>,
    #[serde(rename = "requiredProperties")]
    pub required_properties: Vec<String>,
}

impl Config {
    pub fn get_session_key(&self) -> Key {
        if self.session_key.len() >= 32 {
            Key::from(self.session_key.as_bytes())
        } else {
            Key::generate()
        }
    }

    pub fn get_nacl_public_key(&self) -> Result<Vec<u8>, FromHexError> {
        hex::decode(self.nacl_public_key.trim_start_matches("0x"))
    }

    pub fn get_nacl_secret_key(&self) -> Result<Vec<u8>, FromHexError> {
        hex::decode(self.nacl_secret_key.trim_start_matches("0x"))
    }

    pub fn get_token_builder(&self) -> TokenBuilder {
        TokenBuilder::new(
            &self.token_issuer,
            self.access_token_lifetime,
            &self.access_token_audience,
            self.refresh_token_lifetime,
            &self.refresh_token_audience,
        )
    }
}