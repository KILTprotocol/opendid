use base58::FromBase58;
use serde::{Deserialize, Serialize};
use serde_with::{serde_as, Bytes};
use sodiumoxide::crypto::box_;
use sp_core::H256;
use std::str::FromStr;
use subxt::OnlineClient;

use crate::{
    kilt::{self, KiltConfig},
    routes::error::Error,
};

use super::runtime_types::did::did_details::{DidEncryptionKey, DidPublicKey};

fn parse_key_uri(key_uri: &str) -> Result<(&str, H256), Error> {
    let key_uri_parts: Vec<&str> = key_uri.split('#').collect();
    if key_uri_parts.len() != 2 {
        return Err(Error::InvalidDid("Invalid sender key URI"));
    }
    let did = key_uri_parts[0];
    let key_id = key_uri_parts[1];
    let kid_bs: [u8; 32] = hex::decode(key_id.trim_start_matches("0x"))
        .map_err(|_| Error::InvalidDid("key ID isn't valid hex"))?
        .try_into()
        .map_err(|_| Error::InvalidDid("key ID is expected to have 32 bytes"))?;
    let kid = H256::from(kid_bs);

    Ok((did, kid))
}

pub async fn get_encryption_key_from_fulldid_key_uri(
    key_uri: &str,
    cli: &OnlineClient<KiltConfig>,
) -> Result<box_::PublicKey, Error> {
    let (did, kid) = parse_key_uri(key_uri)?;
    let doc = get_did_doc(did, cli).await?;

    let (_, details) = doc
        .public_keys
        .0
        .iter()
        .find(|&(k, _v)| *k == kid)
        .ok_or(Error::InvalidDid("Could not get sender public key"))?;
    let pk = if let DidPublicKey::PublicEncryptionKey(DidEncryptionKey::X25519(pk)) = details.key {
        pk
    } else {
        return Err(Error::InvalidDid("Invalid sender public key"));
    };
    box_::PublicKey::from_slice(&pk).ok_or(Error::InvalidDid("Invalid sender public key"))
}

pub async fn get_w3n(did: &str, cli: &OnlineClient<KiltConfig>) -> Result<String, Error> {
    let account_id = subxt::utils::AccountId32::from_str(did.trim_start_matches("did:kilt:"))
        .map_err(|_| Error::InvalidDid("Invalid DID"))?;
    let storage_key = kilt::storage().web3_names().names(account_id);
    let name = cli.storage().at_latest().await?.fetch(&storage_key).await?;
    if let Some(name) = name {
        Ok(String::from_utf8(name.0 .0)
            .map_err(|_| Error::InvalidDid("web3name is not valid UTF-8"))?)
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

pub fn parse_encryption_key_from_lightdid(did: &str) -> Result<box_::PublicKey, Error> {
    // example did:kilt:light:00${authAddress}:${details}#encryption
    log::debug!("key uri: {}", did);
    let mut parts = did.split('#');
    let first = parts.next().ok_or(Error::InvalidLightDid("malformed"))?;
    let mut parts = first.split(':').skip(4);
    let details = parts.next().ok_or(Error::InvalidLightDid("malformed"))?;
    log::debug!("details: {}", details);
    let mut chars = details.chars();
    chars.next().ok_or(Error::InvalidLightDid("malformed"))?;
    let bs: Vec<u8> = FromBase58::from_base58(chars.as_str())
        .map_err(|_| Error::InvalidLightDid("malformed base58"))?;
    let details: LightDidDetails =
        serde_cbor::from_slice(&bs[1..]).map_err(|_| Error::InvalidLightDid("malformed cbor"))?;
    box_::PublicKey::from_slice(&details.e.public_key)
        .ok_or(Error::InvalidLightDid("Not a valid public key"))
}

pub async fn get_did_doc(
    did: &str,
    cli: &OnlineClient<KiltConfig>,
) -> Result<kilt::runtime_types::did::did_details::DidDetails, Error> {
    let did = subxt::utils::AccountId32::from_str(did.trim_start_matches("did:kilt:"))
        .map_err(|_| Error::InvalidDid("Invalid DID"))?;
    let did_doc_key = kilt::storage().did().did(&did);
    let details = cli
        .storage()
        .at_latest()
        .await?
        .fetch(&did_doc_key)
        .await?
        .ok_or(Error::InvalidDid("DID not found"))?;
    log::trace!("{:#?}", details);
    Ok(details)
}
