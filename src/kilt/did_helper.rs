use base58::FromBase58;
use serde::{Deserialize, Serialize};
use serde_with::{serde_as, Bytes};
use sodiumoxide::crypto::box_;
use sp_core::H256;
use std::str::FromStr;
use subxt::OnlineClient;

use crate::kilt::{self, KiltConfig};

use super::runtime_types::did::did_details::{DidEncryptionKey, DidPublicKey};

pub async fn get_encryption_key_from_fulldid_key_uri(
    key_uri: &str,
    cli: &OnlineClient<KiltConfig>,
) -> Result<box_::PublicKey, Box<dyn std::error::Error>> {
    let key_uri_parts: Vec<&str> = key_uri.split('#').collect();
    if key_uri_parts.len() != 2 {
        return Err("Invalid sender key URI".into());
    }
    let did = key_uri_parts[0].to_string();
    let key_id = key_uri_parts[1].to_string();
    let kid_bs: [u8; 32] = hex::decode(key_id.trim_start_matches("0x"))?
        .try_into()
        .map_err(|_| "malformed key id")?;
    let kid = H256::from(kid_bs);
    let doc = get_did_doc(&did, cli).await?;
    match doc.public_keys.0.iter().find(|&(k, _v)| *k == kid) {
        Some((_, details)) => {
            let pk = match details.key {
                DidPublicKey::PublicEncryptionKey(DidEncryptionKey::X25519(pk)) => pk,
                _ => return Err("Invalid sender public key".into()),
            };
            box_::PublicKey::from_slice(&pk).ok_or("Invalid sender public key".into())
        }
        _ => Err("Could not get sender public key".into()),
    }
}

pub async fn get_w3n(
    did: &str,
    cli: &OnlineClient<KiltConfig>,
) -> Result<String, Box<dyn std::error::Error>> {
    let account_id = match subxt::utils::AccountId32::from_str(did.trim_start_matches("did:kilt:"))
    {
        Ok(id) => id,
        _ => return Err("Invalid DID".into()),
    };
    let storage_key = kilt::storage().web3_names().names(account_id);
    let name = cli.storage().at_latest().await?.fetch(&storage_key).await?;
    if let Some(name) = name {
        Ok(String::from_utf8(name.0 .0)?)
    } else {
        Ok("".into())
    }
}

#[serde_as]
#[derive(Clone, Debug, Serialize, Deserialize)]
struct LightDidKeyDetails {
    #[serde_as(as = "Bytes")]
    #[serde(rename = "publicKey")]
    public_key: Vec<u8>,
    #[serde(rename = "type")]
    type_: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct LightDidDetails {
    e: LightDidKeyDetails,
}

pub fn parse_encryption_key_from_lightdid(
    did: &str,
) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    // example did:kilt:light:00${authAddress}:${details}#encryption
    log::debug!("key uri: {}", did);
    let mut parts = did.split('#');
    let first = parts.next().ok_or("malformed")?;
    let mut parts = first.split(':').skip(4);
    let details = parts.next().ok_or("malformed")?;
    log::debug!("details: {}", details);
    let mut chars = details.chars();
    chars.next().ok_or("malformed")?;
    let bs: Vec<u8> = FromBase58::from_base58(chars.as_str()).map_err(|_| "malformed base58")?;
    let details: LightDidDetails =
        serde_cbor::from_slice(&bs[1..]).map_err(|_| "malformed cbor")?;
    Ok(details.e.public_key.to_vec())
}

pub async fn get_did_doc(
    did: &str,
    cli: &OnlineClient<KiltConfig>,
) -> Result<kilt::runtime_types::did::did_details::DidDetails, Box<dyn std::error::Error>> {
    let did = match subxt::utils::AccountId32::from_str(did.trim_start_matches("did:kilt:")) {
        Ok(did) => did,
        _ => return Err("Invalid DID".into()),
    };
    let did_doc_key = kilt::storage().did().did(&did);
    let details = cli
        .storage()
        .at_latest()
        .await?
        .fetch(&did_doc_key)
        .await?
        .ok_or("DID not found")?;
    log::info!("{:#?}", details);
    Ok(details)
}
