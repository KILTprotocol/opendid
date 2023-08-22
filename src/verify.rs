use std::str::FromStr;

use hmac::digest::typenum::U32;
use serde_json::json;
use sp_core::{Decode, H256};
use sp_runtime::codec::IoReader;
use sp_runtime::traits::Verify;
use subxt::OnlineClient;

use crate::kilt::runtime_types::attestation::attestations::AttestationDetails;
use crate::kilt::runtime_types::did::did_details::{DidPublicKey, DidVerificationKey};
use crate::kilt::{self, KiltConfig};
use crate::messages::Message;
use crate::routes::{Claim, SubmitCredentialMessageBodyContent};
use crate::util::get_did_doc;

use blake2::{Blake2b, Digest};

type Blake2b256 = Blake2b<U32>;

pub fn hex_encode<T: AsRef<[u8]>>(data: T) -> String {
    format!("0x{}", hex::encode(data.as_ref()))
}

pub fn hex_decode(data: &str) -> Result<Vec<u8>, hex::FromHexError> {
    hex::decode(data.trim_start_matches("0x"))
}

fn normalize_claim(claim: &Claim) -> Result<Vec<String>, Box<dyn std::error::Error>> {
    let mut normalized = Vec::new();

    // First add the owner field like `{"@id":"did:kilt:12345"}`
    let owner_map = serde_json::json!({"@id": claim.owner.clone()});
    normalized.push(serde_json::to_string(&owner_map)?);

    // Now add for every toplevel entry in the contents one object like this:
    // `{"kilt:ctype:12345#Email":"foo@bar.com"}`
    claim
        .contents
        .as_object()
        .ok_or("InvalidClaimContents")?
        .iter()
        .try_for_each(|(key, value)| -> Result<(), Box<dyn std::error::Error>> {
            let key = format!("kilt:ctype:{}#{}", claim.ctype_id, key);
            normalized.push(serde_json::to_string(&json!({ key: value }))?);
            Ok(())
        })?;

    Ok(normalized)
}

/// This will check all disclosed contents against the hashes given in the credential
pub fn check_claim_contents(
    msg: &Message<Vec<SubmitCredentialMessageBodyContent>>,
) -> Result<(), Box<dyn std::error::Error>> {
    msg.body
        .content
        .iter()
        .try_for_each(|content| -> Result<(), Box<dyn std::error::Error>> {
            let normalized_parts = normalize_claim(&content.claim)?;
            // At this point we can calculate the hashes of the normalized statements using blake2b256
            let hashes = normalized_parts
                .iter()
                .map(|part| -> String {
                    let mut hasher = Blake2b256::new();
                    hasher.update(part.as_str());
                    hex_encode(hasher.finalize())
                })
                .collect::<Vec<String>>();

            // Each of these hashes should have a corresponding nonce in the nonce map
            // The nonce hashed together with the hash should be listed in the claim_hashes of the credential
            hashes
                .iter()
                .try_for_each(|hash| -> Result<(), Box<dyn std::error::Error>> {
                    let nonce = content
                        .claim_nonce_map
                        .get(hash)
                        .ok_or("InvalidClaimContents")?;
                    let mut hasher = Blake2b256::new();
                    hasher.update(nonce);
                    hasher.update(hash);
                    let salted_hash = hex_encode(hasher.finalize());
                    if !content.claim_hashes.contains(&salted_hash) {
                        Err("InvalidClaimContents".into())
                    } else {
                        Ok(())
                    }
                })?;
            Ok(())
        })?;

    // Claims are valid if we get here!
    Ok(())
}

/// Hashing the claim-hashes together should result in the root hash of the credential
pub fn check_root_hash(
    msg: &Message<Vec<SubmitCredentialMessageBodyContent>>,
) -> Result<(), Box<dyn std::error::Error>> {
    msg.body
        .content
        .iter()
        .try_for_each(|content| -> Result<(), Box<dyn std::error::Error>> {
            let mut hasher = Blake2b256::new();
            for hash in content.claim_hashes.iter() {
                let data = hex_decode(hash)?;
                hasher.update(&data);
            }
            let root_hash = hex_encode(hasher.finalize());
            if root_hash != content.root_hash {
                Err("InvalidRootHash".into())
            } else {
                Ok(())
            }
        })
}

pub async fn check_signature(
    msg: &Message<Vec<SubmitCredentialMessageBodyContent>>,
    challenge: &Vec<u8>,
    cli: &OnlineClient<KiltConfig>,
) -> Result<(), Box<dyn std::error::Error>> {
    log::info!("Checking signature");
    for content in msg.body.content.iter() {
        log::info!("Checking signature for claim: {:#?}", content);
        // get the public key from the chain
        let did = content.claim.owner.clone();
        let public_key = get_auth_pubkey(&did, cli).await?;
        // get the signature from the message
        let signature = hex_decode(content.claimer_signature.signature.trim_start_matches("0x"))?;
        // get the root hash from the message
        let root_hash = hex_decode(content.root_hash.trim_start_matches("0x"))?;

        // verify the signature
        let signature_data = [root_hash, challenge.to_owned()].concat();
        let valid = {
            if let Ok(signature) =
                sp_runtime::MultiSignature::decode(&mut IoReader(signature.as_slice()))
            {
                signature.verify(signature_data.as_slice(), &public_key)
            } else if let Ok(signature) =
                sp_core::sr25519::Signature::decode(&mut IoReader(signature.as_slice()))
            {
                signature.verify(
                    signature_data.as_slice(),
                    &sp_core::sr25519::Public(public_key.into()),
                )
            } else if let Ok(signature) =
                sp_core::ed25519::Signature::decode(&mut IoReader(signature.as_slice()))
            {
                signature.verify(
                    signature_data.as_slice(),
                    &sp_core::ed25519::Public(public_key.into()),
                )
            } else {
                false
            }
        };
        if !valid {
            return Err("Could not verify signature".into());
        }
    }
    Ok(())
}

async fn check_attestation(
    msg: &Message<Vec<SubmitCredentialMessageBodyContent>>,
    cli: &OnlineClient<KiltConfig>,
) -> Result<Vec<AttestationDetails>, Box<dyn std::error::Error>> {
    let mut attestations = Vec::new();
    for content in msg.body.content.iter() {
        let attestation = get_attestation(&content.root_hash, cli).await?;
        log::info!("Attestation found on chain: {:?}", attestation);

        // check if it is  not revoked
        if attestation.revoked {
            return Err("Attestation is revoked".into());
        }
        log::info!("Attestation not revoked");
        attestations.push(attestation);
    }
    Ok(attestations)
}

pub async fn verify_credential_message(
    msg: &Message<Vec<SubmitCredentialMessageBodyContent>>,
    challenge: Vec<u8>,
    cli: &OnlineClient<KiltConfig>,
) -> Result<Vec<AttestationDetails>, Box<dyn std::error::Error>> {
    check_claim_contents(msg)?;
    log::info!("Claim contents verified");
    check_root_hash(msg)?;
    log::info!("Root hash verified");
    check_signature(msg, &challenge, cli).await?;
    log::info!("Claimer signature verified");
    let attestations = check_attestation(msg, cli).await?;
    log::info!("Attestation verified");
    Ok(attestations)
}

async fn get_auth_pubkey(
    did: &str,
    cli: &OnlineClient<KiltConfig>,
) -> Result<sp_runtime::AccountId32, Box<dyn std::error::Error>> {
    let doc = get_did_doc(did, cli).await?;
    let auth_key_id = doc.authentication_key;
    let pubkey_details = &doc
        .public_keys
        .0
        .iter()
        .find(|&(k, _v)| *k == auth_key_id)
        .ok_or("Could not get auth key")?
        .1;
    match &pubkey_details.key {
        DidPublicKey::PublicVerificationKey(DidVerificationKey::Sr25519(pk)) => {
            Ok(sp_runtime::AccountId32::from(pk.0))
        }
        DidPublicKey::PublicVerificationKey(DidVerificationKey::Ed25519(pk)) => {
            Ok(sp_runtime::AccountId32::from(pk.0))
        }
        _ => Err("Invalid auth key".into()),
    }
}

async fn get_attestation(
    hash: &str,
    cli: &OnlineClient<KiltConfig>,
) -> Result<AttestationDetails, Box<dyn std::error::Error>> {
    let hash = match H256::from_str(hash.trim_start_matches("0x")) {
        Ok(hash) => hash,
        _ => return Err("Invalid hash".into()),
    };
    let addr = kilt::storage().attestation().attestations(hash);
    let attestation = cli
        .storage()
        .at_latest()
        .await?
        .fetch(&addr)
        .await?
        .ok_or("Attestation not found")?;
    Ok(attestation)
}
