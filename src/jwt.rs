use hmac::{Hmac, Mac};
use jwt::{PKeyWithDigest, SignWithKey, SigningAlgorithm, VerifyWithKey, VerifyingAlgorithm};
use openssl::{hash::MessageDigest, pkey::PKey};
use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize, Deserialize)]
pub struct Token {
    #[serde(rename = "sub")]
    pub subject: String,
    #[serde(rename = "w3n")]
    pub name: String,
    #[serde(rename = "exp")]
    pub expiry: i64,
    #[serde(rename = "iat")]
    pub issued_at: i64,
    #[serde(rename = "iss")]
    pub issuer: String,
    #[serde(rename = "aud")]
    pub audience: String,
    #[serde(rename = "pro")]
    pub properties: serde_json::Map<String, serde_json::Value>,
    #[serde(rename = "nonce")]
    pub nonce: Option<String>,
}

impl Token {
    pub fn to_jwt(&self, secret: &str, alg: &str) -> Result<String, Box<dyn std::error::Error>> {
        let key: Box<dyn SigningAlgorithm> = match alg {
            "HS256" => Box::new(Hmac::<sha2::Sha256>::new_from_slice(secret.as_bytes())?),
            "HS384" => Box::new(Hmac::<sha2::Sha384>::new_from_slice(secret.as_bytes())?),
            "HS512" => Box::new(Hmac::<sha2::Sha512>::new_from_slice(secret.as_bytes())?),
            "RS256" | "ES256" => Box::new(PKeyWithDigest {
                digest: MessageDigest::sha256(),
                key: PKey::private_key_from_pem(secret.as_bytes())?,
            }),
            "RS384" | "ES384" => Box::new(PKeyWithDigest {
                digest: MessageDigest::sha384(),
                key: PKey::private_key_from_pem(secret.as_bytes())?,
            }),
            "RS512" | "ES512" => Box::new(PKeyWithDigest {
                digest: MessageDigest::sha512(),
                key: PKey::private_key_from_pem(secret.as_bytes())?,
            }),
            _ => return Err("unsupported algorithm".into()),
        };
        let jwt = self.sign_with_key(&key)?;
        Ok(jwt)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TokenFactory {
    issuer: String,
    access_token_lifetime: i64,
    access_token_audience: String,
    refresh_token_lifetime: i64,
    refresh_token_audience: String,
}

impl TokenFactory {
    pub fn new(
        issuer: &str,
        access_token_lifetime: i64,
        access_token_audience: &str,
        refresh_token_lifetime: i64,
        refresh_token_audience: &str,
    ) -> Self {
        Self {
            issuer: issuer.to_string(),
            access_token_lifetime,
            access_token_audience: access_token_audience.to_string(),
            refresh_token_lifetime,
            refresh_token_audience: refresh_token_audience.to_string(),
        }
    }

    pub fn new_id_token(
        &self,
        subject: &str,
        web3_name: &str,
        properties: &serde_json::Map<String, serde_json::Value>,
        nonce: &Option<String>,
    ) -> Token {
        let now = chrono::Utc::now();
        let expiry = now.timestamp() + self.access_token_lifetime;
        Token {
            subject: subject.to_string(),
            name: web3_name.into(),
            expiry,
            issued_at: now.timestamp(),
            issuer: self.issuer.clone(),
            audience: self.access_token_audience.clone(),
            properties: properties.clone(),
            nonce: nonce.to_owned(),
        }
    }

    pub fn new_refresh_token(
        &self,
        subject: &str,
        web3_name: &str,
        properties: &serde_json::Map<String, serde_json::Value>,
        nonce: &Option<String>,
    ) -> Token {
        let now = chrono::Utc::now();
        let expiry = now.timestamp() + self.refresh_token_lifetime;
        Token {
            subject: subject.to_string(),
            name: web3_name.into(),
            expiry,
            issued_at: now.timestamp(),
            issuer: self.issuer.clone(),
            audience: self.refresh_token_audience.clone(),
            properties: properties.clone(),
            nonce: nonce.to_owned(),
        }
    }

    pub fn parse_token(
        &self,
        token: &str,
        secret: &str,
        alg: &str,
    ) -> Result<Token, Box<dyn std::error::Error>> {
        let key: Box<dyn VerifyingAlgorithm> = match alg {
            "HS256" => Box::new(Hmac::<sha2::Sha256>::new_from_slice(secret.as_bytes())?),
            "HS384" => Box::new(Hmac::<sha2::Sha384>::new_from_slice(secret.as_bytes())?),
            "HS512" => Box::new(Hmac::<sha2::Sha512>::new_from_slice(secret.as_bytes())?),
            "RS256" | "ES256" => Box::new(PKeyWithDigest {
                digest: MessageDigest::sha256(),
                key: PKey::public_key_from_pem(secret.as_bytes())?,
            }),
            "RS384" | "ES384" => Box::new(PKeyWithDigest {
                digest: MessageDigest::sha384(),
                key: PKey::public_key_from_pem(secret.as_bytes())?,
            }),
            "RS512" | "ES512" => Box::new(PKeyWithDigest {
                digest: MessageDigest::sha512(),
                key: PKey::public_key_from_pem(secret.as_bytes())?,
            }),
            _ => return Err("unsupported algorithm".into()),
        };
        let token = token.verify_with_key(&key)?;
        Ok(token)
    }

    pub fn parse_refresh_token(
        &self,
        token: &str,
        key: &str,
        alg: &str,
    ) -> Result<Token, Box<dyn std::error::Error>> {
        let token = self.parse_token(token, key, alg)?;
        // check audience
        if token.audience != self.refresh_token_audience {
            return Err("invalid audience".into());
        }
        // check expiry
        let now = chrono::Utc::now();
        if token.expiry < now.timestamp() {
            return Err("token expired".into());
        }
        // check issued at
        if token.issued_at > now.timestamp() {
            return Err("token issued in the future".into());
        }
        // check issuer
        if token.issuer != self.issuer {
            return Err("invalid issuer".into());
        }
        Ok(token)
    }
}

// tests
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_token() {
        let token = Token {
            subject: "test".to_string(),
            name: "test".to_string(),
            expiry: 0,
            issued_at: 0,
            issuer: "test".to_string(),
            audience: "test".to_string(),
            properties: serde_json::Map::new(),
            nonce: None,
        };
        let secret = "secret";
        let jwt = token.to_jwt(secret, "HS256").unwrap();
        println!("{jwt}");
    }

    #[test]
    fn test_token_builder() {
        let token_builder = TokenFactory::new(
            "did:kilt:verifier",
            30,
            "application",
            60 * 60 * 24,
            "authentication",
        );
        let secret = "secret";
        let access_token =
            token_builder.new_id_token("did:kilt:user", "user", &serde_json::Map::new(), &None);
        let jwt = access_token.to_jwt(secret, "HS256").unwrap();
        println!("access_token {jwt}");
        let refresh_token = token_builder.new_refresh_token(
            "did:kilt:user",
            "user",
            &serde_json::Map::new(),
            &None,
        );
        let jwt = refresh_token.to_jwt(secret, "HS256").unwrap();
        println!("refresh_token {jwt}");
    }
}
