use std::collections::HashMap;

use actix_web::cookie::Key;
use hex::FromHexError;
use serde::{Deserialize, Serialize};

use crate::jwt::TokenFactory;

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Config {
    pub host: String,
    pub port: u16,
    pub production: bool,
    pub kilt_endpoint: Option<String>,
    pub base_path: String,
    pub session: SessionConfig,
    pub jwt: JWTConfig,
    #[serde(rename = "wellKnownDid")]
    pub well_known_did_config: WellKnownDidConfig,
    pub clients: HashMap<String, ClientConfig>,
    pub etcd: Option<EtcdConfig>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SessionConfig {
    pub session_key: String,
    pub key_uri: String,
    pub nacl_public_key: String,
    pub nacl_secret_key: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct JWTConfig {
    pub token_issuer: String,
    pub algorithm: String,
    pub secret_key: String,
    pub public_key: Option<String>,
    pub access_token_lifetime: i64,
    pub access_token_audience: String,
    pub refresh_token_lifetime: i64,
    pub refresh_token_audience: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CredentialRequirement {
    #[serde(rename = "cTypeHash")]
    pub ctype_hash: String,
    pub trusted_attesters: Vec<String>,
    pub required_properties: Vec<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct WellKnownDidConfig {
    pub did: String,
    pub key_uri: String,
    pub origin: String,
    pub seed: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct EtcdConfig {
    pub endpoints: Vec<String>,
    #[serde(flatten)]
    pub user_auth: Option<EtcdUserAuth>,
    #[serde(flatten)]
    pub tls_auth: Option<EtcdTlsAuth>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct EtcdUserAuth {
    pub username: String,
    pub password: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct EtcdTlsAuth {
    pub domain_name: String,
    pub ca_cert: String,
    #[serde(flatten)]
    pub client_auth: Option<EtcdTlsClientAuth>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct EtcdTlsClientAuth {
    pub client_cert: String,
    pub client_key: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ClientConfig {
    pub requirements: Vec<CredentialRequirement>,
    #[serde(rename = "redirectUrls")]
    pub redirect_urls: Vec<String>,
}

impl Config {
    pub fn get_session_key(&self) -> Key {
        if self.session.session_key.len() >= 32 {
            Key::from(
                hex::decode(self.session.session_key.trim_start_matches("0x"))
                    .expect("session key is not a valid hex string")
                    .as_slice(),
            )
        } else {
            Key::generate()
        }
    }

    pub fn get_nacl_public_key(&self) -> Result<Vec<u8>, FromHexError> {
        hex::decode(self.session.nacl_public_key.trim_start_matches("0x"))
    }

    pub fn get_nacl_secret_key(&self) -> Result<Vec<u8>, FromHexError> {
        hex::decode(self.session.nacl_secret_key.trim_start_matches("0x"))
    }

    pub fn get_token_factory(&self) -> TokenFactory {
        TokenFactory::new(
            &self.jwt.token_issuer,
            self.jwt.access_token_lifetime,
            &self.jwt.access_token_audience,
            self.jwt.refresh_token_lifetime,
            &self.jwt.refresh_token_audience,
        )
    }
}
