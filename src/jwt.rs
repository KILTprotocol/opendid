use serde::{Serialize, Deserialize};

#[derive(Debug, Serialize, Deserialize)]
pub struct Token {
    #[serde(rename = "sub")]
    pub subject: String,
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
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TokenBuilder {
    issuer: String,
    access_token_lifetime: i64,
    access_token_audience: String,
    refresh_token_lifetime: i64,
    refresh_token_audience: String,
}

impl TokenBuilder {
    pub fn new(issuer: &str, access_token_lifetime: i64, access_token_audience: &str, refresh_token_lifetime: i64, refresh_token_audience: &str) -> Self {
        Self {
            issuer: issuer.to_string(),
            access_token_lifetime,
            access_token_audience: access_token_audience.to_string(),
            refresh_token_lifetime,
            refresh_token_audience: refresh_token_audience.to_string(),
        }
    }

    pub fn new_access_token(&self, subject: &str, properties: serde_json::Map<String, serde_json::Value>) -> Token {
        let now = chrono::Utc::now();
        let expiry = now.timestamp() + self.access_token_lifetime;
        Token {
            subject: subject.to_string(),
            expiry: expiry,
            issued_at: now.timestamp(),
            issuer: self.issuer.clone(),
            audience: self.access_token_audience.clone(),
            properties,
        }
    }

    pub fn new_refresh_token(&self, subject: &str, properties: serde_json::Map<String, serde_json::Value>) -> Token {
        let now = chrono::Utc::now();
        let expiry = now.timestamp() + self.refresh_token_lifetime;
        Token {
            subject: subject.to_string(),
            expiry: expiry,
            issued_at: now.timestamp(),
            issuer: self.issuer.clone(),
            audience: self.refresh_token_audience.clone(),
            properties,
        }
    }
}


use hmac::{Hmac, Mac};
use jwt::SignWithKey;
use sha2::Sha256;

impl Token {
    pub fn to_jwt(&self, secret: &str) -> Result<String, Box<dyn std::error::Error>> {
        let key: Hmac<Sha256> = Hmac::new_from_slice(secret.as_bytes())?;
        let jwt = self.sign_with_key(&key)?;
        Ok(jwt)
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
            expiry: 0,
            issued_at: 0,
            issuer: "test".to_string(),
            audience: "test".to_string(),
            properties: serde_json::Map::new(),
        };
        let secret = "secret";
        let jwt = token.to_jwt(secret).unwrap();
        println!("{}", jwt);
    }

    #[test]
    fn test_token_builder() {
        let token_builder = TokenBuilder::new(
            "did:kilt:verifier",
            30,
            "application", 
            60*60*24,
            "authentication",
        );
        let secret = "secret";
        let access_token = token_builder.new_access_token("did:kilt:user", serde_json::Map::new());
        let jwt = access_token.to_jwt(secret).unwrap();
        println!("access_token {}", jwt);
        let refresh_token = token_builder.new_refresh_token("did:kilt:user", serde_json::Map::new());
        let jwt = refresh_token.to_jwt(secret).unwrap();
        println!("refresh_token {}", jwt);
    }
}