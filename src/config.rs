use std::collections::HashMap;

use actix_web::cookie::Key;
use hex::FromHexError;
use serde::{Deserialize, Serialize};

use crate::jwt::TokenBuilder;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Config {
    pub host: String,
    pub port: u16,
    #[serde(rename = "basePath")]
    pub base_path: String,
    #[serde(rename = "credentialRequirements")]
    pub credential_requirements: Vec<CredentialRequirement>,
    #[serde(rename = "session")]
    pub session_config: SessionConfig,
    #[serde(rename = "jwt")]
    pub jwt_config: JWTConfig,
    #[serde(rename = "wellKnownDid")]
    pub well_known_did_config: WellKnownDidConfig,
    #[serde(rename = "oauth")]
    pub oauth_config: Option<OauthConfig>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SessionConfig {
    #[serde(rename = "sessionKey")]
    pub session_key: String,
    #[serde(rename = "keyUri")]
    pub key_uri: String,
    #[serde(rename = "naclPublicKey")]
    pub nacl_public_key: String,
    #[serde(rename = "naclSecretKey")]
    pub nacl_secret_key: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct JWTConfig {
    #[serde(rename = "tokenIssuer")]
    pub token_issuer: String,
    #[serde(rename = "tokenSecret")]
    pub token_secret: String,
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
    #[serde(rename = "regexCheck")]
    pub regex_check: Option<RegexCheck>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RegexCheck {
    pub selector: String,
    pub regex: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct WellKnownDidConfig {
    pub did: String,
    #[serde(rename = "keyUri")]
    pub key_uri: String,
    pub origin: String,
    pub seed: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct OauthConfig {
    #[serde(rename = "redirectUrls")]
    pub redirect_urls: HashMap<String, Vec<String>>,
}

impl Config {
    pub fn get_session_key(&self) -> Key {
        if self.session_config.session_key.len() >= 32 {
            Key::from(hex::decode(self.session_config.session_key.trim_start_matches("0x")).unwrap().as_slice())
        } else {
            Key::generate()
        }
    }

    pub fn get_nacl_public_key(&self) -> Result<Vec<u8>, FromHexError> {
        hex::decode(self.session_config.nacl_public_key.trim_start_matches("0x"))
    }

    pub fn get_nacl_secret_key(&self) -> Result<Vec<u8>, FromHexError> {
        hex::decode(self.session_config.nacl_secret_key.trim_start_matches("0x"))
    }

    pub fn get_token_builder(&self) -> TokenBuilder {
        TokenBuilder::new(
            &self.jwt_config.token_issuer,
            self.jwt_config.access_token_lifetime,
            &self.jwt_config.access_token_audience,
            self.jwt_config.refresh_token_lifetime,
            &self.jwt_config.refresh_token_audience,
        )
    }
}
