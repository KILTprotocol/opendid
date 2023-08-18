use std::collections::HashMap;

use hmac::digest::typenum::U32;
use serde::{Serialize, Deserialize};
use serde_json::json;
use blake2::{Blake2b, Digest};
use sp_core::Pair;
use crate::{verify::{hex_encode, hex_decode}, config};

type Blake2b256 = Blake2b<U32>;

/*
This file contains the structs and functions to parse the well-known DID configuration file and also produce the well-known DID configuration file.
An example of a did config is this:
```json
{
  "@context": "https://identity.foundation/.well-known/did-configuration/v1",
  "linked_dids": [
    {
      "@context": [
        "https://www.w3.org/2018/credentials/v1",
        "https://identity.foundation/.well-known/did-configuration/v1"
      ],
      "issuer": "did:kilt:4pnfkRn5UurBJTW92d9TaVLR2CqJdY4z5HPjrEbpGyBykare",
      "issuanceDate": "2023-06-30T10:49:26.523Z",
      "expirationDate": "2028-06-28T10:49:26.523Z",
      "type": [
        "VerifiableCredential",
        "DomainLinkageCredential",
        "KiltCredential2020"
      ],
      "credentialSubject": {
        "id": "did:kilt:4pnfkRn5UurBJTW92d9TaVLR2CqJdY4z5HPjrEbpGyBykare",
        "origin": "https://socialkyc.io",
        "rootHash": "0xafac89ab60c40fd17c4406ac7585516c4e159d61b1cab9aad442dda2fba90d33"
      },
      "proof": {
        "type": "KILTSelfSigned2020",
        "proofPurpose": "assertionMethod",
        "verificationMethod": "did:kilt:4pnfkRn5UurBJTW92d9TaVLR2CqJdY4z5HPjrEbpGyBykare#0xbcb574af4617bda1f2528606b241c2e23f56cf20a054decf938c0d9c2b65a6f8",
        "signature": "0x1adbc099321704bad843be9e4977aae76022aa4c3d0f11eda335251ab1047512a1c95c38701f28d30b80d936e6b30350d40e04fe49385c6eab49cb47b304d98c"
      }
    }
  ]
}
```
*/
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct WellKnownDidConfig {
    pub context: String,
    pub linked_dids: Vec<LinkedDid>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct LinkedDid {
    pub context: Vec<String>,
    pub issuer: String,
    #[serde(rename = "issuanceDate")]
    pub issuance_date: String,
    #[serde(rename = "expirationDate")]
    pub expiration_date: String,
    #[serde(rename = "type")]
    pub type_: Vec<String>,
    #[serde(rename = "credentialSubject")]
    pub credential_subject: CredentialSubject,
    pub proof: Proof,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct CredentialSubject {
    pub id: String,
    pub origin: String,
    #[serde(rename = "rootHash")]
    pub root_hash: String,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct Proof {
    #[serde(rename = "type")]
    pub type_: String,
    #[serde(rename = "proofPurpose")]
    pub proof_purpose: String,
    #[serde(rename = "verificationMethod")]
    pub verification_method: String,
    pub signature: String,
}

impl WellKnownDidConfig {
    pub fn new<P: sp_core::Pair>(
        id: &str,
        origin: &str,
        verification_method: &str,
        signer: &P,
    ) -> Result<Self, Box<dyn std::error::Error>> {
        let normalized = [
            serde_json::to_string(&json!({"@id": id}))?,
            serde_json::to_string(&json!({"kilt:ctype:0x9d271c790775ee831352291f01c5d04c7979713a5896dcf5e81708184cc5c643#id": id}))?,
            serde_json::to_string(&json!({"kilt:ctype:0x9d271c790775ee831352291f01c5d04c7979713a5896dcf5e81708184cc5c643#origin": origin}))?,
        ];
        let hashes = normalized
            .iter()
            .map(|part| -> String {
                let mut hasher = Blake2b256::new();
                hasher.update(part.as_str());
                hex_encode(hasher.finalize())
            })
            .collect::<Vec<String>>();
        let (_nonce_map, salted_hashes) = {
            let mut nonces = HashMap::new();
            let mut salted_hashes = Vec::new();
            hashes.iter().for_each(|hash| {
                let nonce = uuid::Uuid::new_v4().to_string();
                let mut hasher = Blake2b256::new();
                hasher.update(nonce.as_str());
                hasher.update(hash.as_str());
                let salted_hash = hex_encode(hasher.finalize());
                salted_hashes.push(salted_hash.clone());
                nonces.insert(hash.clone(), nonce);
            });
            (nonces, salted_hashes)
        };
        let mut hasher = Blake2b256::new();
        salted_hashes.iter().try_for_each(|salted_hash| -> Result<(), Box<dyn std::error::Error>> {
            hasher.update(hex_decode(salted_hash.as_str())?);
            Ok(())
        })?;
        let root_hash = hex_encode(hasher.finalize());
        let signature = signer.sign(&hex_decode(root_hash.as_str())?);
        let proof = Proof {
            type_: "KILTSelfSigned2020".to_string(),
            proof_purpose: "assertionMethod".to_string(),
            verification_method: verification_method.to_string(),
            signature: hex_encode(signature),
        };
        let subject = CredentialSubject {
            id: id.to_string(),
            origin: origin.to_string(),
            root_hash,
        };
        Ok(WellKnownDidConfig {
            context: "https://identity.foundation/.well-known/did-configuration/v1".to_string(),
            linked_dids: [
                LinkedDid::new(id, subject, proof),
            ].into(),
        })
    }

}

impl LinkedDid {
    pub fn new(issuer: &str, subject: CredentialSubject, proof: Proof) -> Self {
        let now = chrono::Utc::now();
        let expiration_date = now + chrono::Duration::days(365);
        let expiration_date = expiration_date.format("%Y-%m-%dT%H:%M:%S%.3fZ").to_string();
        let issuance_date = now.format("%Y-%m-%dT%H:%M:%S%.3fZ").to_string();
        LinkedDid {
            context: vec![
                "https://www.w3.org/2018/credentials/v1".to_string(),
                "https://identity.foundation/.well-known/did-configuration/v1".to_string(),
            ],
            issuer: issuer.to_string(),
            credential_subject: subject,
            issuance_date,
            expiration_date,
            proof,
            type_: vec![
                "VerifiableCredential".to_string(),
                "DomainLinkageCredential".to_string(),
                "KiltCredential2020".to_string(),
            ],
        }
    }
}

pub fn create_well_known_did_config(cfg: &config::WellKnownDidConfig) -> Result<WellKnownDidConfig, Box<dyn std::error::Error>> {
    let pair = sp_core::sr25519::Pair::from_string_with_seed(&cfg.seed, None)?.0;
    let doc = WellKnownDidConfig::new(
        &cfg.did,
        &cfg.origin,
        &cfg.key_uri,
        &pair,
    )?;
    Ok(doc)
}