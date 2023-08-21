use std::str::FromStr;

use base58::FromBase58;
use serde::{Deserialize, Serialize};
use serde_with::{serde_as, Bytes};
use subxt::OnlineClient;

use crate::kilt::{self, KiltConfig};

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
    log::info!("key uri: {}", did);
    let mut parts = did.split('#');
    let first = parts.next().ok_or("malformed")?;
    let mut parts = first.split(':');
    let _ = parts.next().ok_or("malformed")?;
    let _ = parts.next().ok_or("malformed")?;
    let _ = parts.next().ok_or("malformed")?;
    let _ = parts.next().ok_or("malformed")?;
    let details = parts.next().ok_or("malformed")?;
    log::info!("details: {}", details);
    let bs: Vec<u8> = FromBase58::from_base58(&details[1..]).map_err(|_| "malformed base58")?;
    log::info!("bs: {:?}", bs);
    let details: LightDidDetails = match serde_cbor::from_slice(&bs[1..]) {
        Ok(details) => details,
        Err(err) => {
            log::error!("Error: {}", err);
            return Err("malformed cbor".into());
        }
    };
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
