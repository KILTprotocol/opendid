use std::{collections::HashMap, str::FromStr};

use actix_session::Session;
use actix_web::{get, post, web, HttpResponse};
use serde::{Deserialize, Serialize};
use serde_json::json;
use sodiumoxide::crypto::box_;
use sp_core::{crypto::Ss58Codec, H256};

use subxt::OnlineClient;

use crate::{
    config::CredentialRequirement,
    kilt::{
        self,
        runtime_types::did::did_details::{DidEncryptionKey, DidPublicKey},
        KiltConfig,
    },
    messages::{EncryptedMessage, Message, MessageBody},
    routes::{error::Error, AuthorizeQueryParameters},
    util::{get_did_doc, parse_encryption_key_from_lightdid},
    verify::verify_credential_message,
    AppState,
};

#[derive(Clone, Debug, Serialize, Deserialize)]
struct RequestCredentialMessageBodyContent {
    #[serde(rename = "cTypes")]
    ctypes: Vec<CredentialRequirement>,
    challenge: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SubmitCredentialMessageBodyContent {
    pub claim: Claim,
    #[serde(rename = "claimNonceMap")]
    pub claim_nonce_map: HashMap<String, String>,
    #[serde(rename = "claimHashes")]
    pub claim_hashes: Vec<String>,
    #[serde(rename = "delegationId")]
    pub delegation_id: Option<String>,
    pub legitimations: Vec<serde_json::Value>,
    #[serde(rename = "claimerSignature")]
    pub claimer_signature: DidSignature,
    #[serde(rename = "rootHash")]
    pub root_hash: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Claim {
    #[serde(rename = "cTypeHash")]
    pub ctype_id: String,
    pub contents: serde_json::Value,
    pub owner: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct DidSignature {
    #[serde(rename = "keyUri")]
    pub key_uri: String,
    pub signature: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PostCredentialQueryParameter {
    pub redirect: Option<String>,
}

#[get("/api/v1/credentials")]
async fn get_credential_requirements_handler(
    app_state: web::Data<AppState>,
    session: Session,
) -> Result<HttpResponse, Error> {
    log::info!("GET credential requirements handler");
    let key_uri = session
        .get::<String>("key_uri")?
        .ok_or(Error::SessionGet)?;
    let challenge = format!("0x{}", hex::encode(box_::gen_nonce()));
    session.insert("credential-challenge", challenge.clone())?;
    let sender = app_state
        .encryption_key_uri
        .split('#')
        .collect::<Vec<&str>>().first()
        .ok_or(Error::InvalidPrivateKey)?
        .to_owned();
    let msg = Message {
        body: MessageBody {
            type_: "request-credential".to_string(),
            content: RequestCredentialMessageBodyContent {
                ctypes: app_state.credential_requirements.clone(),
                challenge,
            },
        },
        created_at: 0,
        sender: sender.to_string(),
        receiver: key_uri.clone(),
        message_id: uuid::Uuid::new_v4().to_string(),
        in_reply_to: None,
        references: None,
    };
    let msg_json = serde_json::to_string(&msg).unwrap();
    let msg_bytes = msg_json.as_bytes();
    let our_secretkey = app_state.secret_key.clone();
    let others_pubkey =
        parse_encryption_key_from_lightdid(key_uri.as_str()).map_err(|_| Error::InvalidLightDid)?;
    let nonce = box_::gen_nonce();
    let pk = box_::PublicKey::from_slice(&others_pubkey).ok_or(Error::InvalidLightDid)?;
    let sk = box_::SecretKey::from_slice(&our_secretkey).ok_or(Error::InvalidPrivateKey)?;
    let encrypted_msg = box_::seal(msg_bytes, &nonce, &pk, &sk);
    let encrypted_msg_hex = format!("0x{}", hex::encode(encrypted_msg));
    let nonce_hex = format!("0x{}", hex::encode(nonce));
    let response = EncryptedMessage {
        cipher_text: encrypted_msg_hex,
        nonce: nonce_hex,
        sender_key_uri: app_state.encryption_key_uri.clone(),
        receiver_key_uri: key_uri,
    };
    Ok(HttpResponse::Ok().json(response))
}

#[post("/api/v1/credentials")]
async fn post_credential_handler(
    app_state: web::Data<AppState>,
    session: Session,
    body: web::Json<EncryptedMessage>,
    query: web::Query<PostCredentialQueryParameter>,
) -> Result<HttpResponse, Error> {
    log::info!("POST credential handler");

    let cli = kilt::connect("spiritnet")
        .await
        .map_err(|_| Error::CantConnectToBlockchain)?;
    let pk = get_encryption_key_from_fulldid_key_uri(&body.sender_key_uri, &cli)
        .await
        .map_err(|_| Error::InvalidFullDid)?;

    let nonce_bytes =
        hex::decode(body.nonce.trim_start_matches("0x")).map_err(|_| Error::InvalidNonce)?;
    let nonce = box_::Nonce::from_slice(&nonce_bytes).ok_or(Error::InvalidNonce)?;
    let cipher_text = hex::decode(body.cipher_text.trim_start_matches("0x"))
        .map_err(|_| Error::FailedToDecrypt)?;
    let sk = box_::SecretKey::from_slice(&app_state.secret_key).ok_or(Error::InvalidPrivateKey)?;
    let decrypted_msg =
        box_::open(&cipher_text, &nonce, &pk, &sk).map_err(|_| Error::FailedToDecrypt)?;

    let content: Message<Vec<SubmitCredentialMessageBodyContent>> =
        serde_json::from_slice(&decrypted_msg).map_err(|_| Error::FailedToParseMessage)?;

    let challenge_hex = session
        .get::<String>("credential-challenge")?
        .ok_or(Error::GetChallenge)?;
    let challenge =
        hex::decode(challenge_hex.trim_start_matches("0x")).map_err(|_| Error::GetChallenge)?;

    let attestations = verify_credential_message(&content, challenge, &cli)
        .await
        .map_err(|e| Error::VerifyCredential(format!("{}", e)))?;

    // go through all credential requirements and check that at least one is fulfilled with the given cred
    let mut fulfilled = false;
    let mut props = serde_json::Map::new();

    for (i, attestation) in attestations.iter().enumerate() {
        let content = &content.body.content[i];
        let credential_attester_did = format!(
            "did:kilt:{}",
            sp_runtime::AccountId32::from(attestation.attester.0)
                .to_ss58check_with_version(38u16.into())
        );

        for requirement in &app_state.credential_requirements {
            if requirement.ctype_hash != content.claim.ctype_id {
                log::info!("Requirement ctype hash does not match");
                continue;
            }
            if !requirement
                .trusted_attesters
                .contains(&credential_attester_did)
            {
                log::info!("Requirement attester DID does not match");
                continue;
            }
            // go through all required properties and check they are in the attestation
            let mut properties_fulfilled = true;
            let content_object = match content.claim.contents.as_object() {
                Some(data) => data,
                _ => return Ok(HttpResponse::BadRequest().body("Could not get claim contents")),
            };
            for property in &requirement.required_properties {
                if !content_object.contains_key(property) {
                    log::info!("Requirement property '{}' not found", property);
                    properties_fulfilled = false;
                    break;
                }
            }
            if !properties_fulfilled {
                log::info!("Requirement properties not fulfilled");
                continue;
            }
            log::info!("Requirement fulfilled");
            fulfilled = true;
            break;
        }

        if fulfilled {
            for (key, value) in content.claim.contents.as_object().unwrap() {
                props.insert(key.clone(), value.clone());
            }
            break;
        }
    }

    if !fulfilled {
        log::info!("No credential requirement fulfilled");
        return Err(Error::VerifyCredential(
            "No credential requirement fulfilled".into(),
        ));
    }

    let oauth_context = match session.get::<AuthorizeQueryParameters>("oauth-context") {
        Ok(data) => data,
        _ => None,
    };
    let nonce = oauth_context.clone().map(|data| data.nonce);

    log::info!("Credential checked, all good to go");

    let w3n = get_w3n(&content.sender, &cli).await.unwrap_or("".into());

    let access_token = app_state
        .token_builder
        .new_access_token(&content.sender, &w3n, &props, &nonce)
        .to_jwt(&app_state.token_secret)
        .map_err(|_| Error::CreateJWT)?;

    let refresh_token = app_state
        .token_builder
        .new_refresh_token(&content.sender, &w3n, &props, &nonce)
        .to_jwt(&app_state.token_secret)
        .map_err(|_| Error::CreateJWT)?;

    // in case we have a redirect url, redirect to it with the tokens as query parameters
    // thats the simple custom flow
    if let Some(redirect_url) = &query.redirect {
        return Ok(HttpResponse::Found()
            .append_header((
                "Location",
                format!(
                    "{}?access_token={}&refresh_token={}",
                    redirect_url, access_token, refresh_token
                ),
            ))
            .finish());
    }

    match &oauth_context {
        Some(context) => {
            log::info!("Got oauth context from session");
            Ok(HttpResponse::Found()
                .append_header((
                    "Location",
                    format!(
                        "{}?access_token={}&refresh_token={}&state={}",
                        context.redirect_uri.clone(),
                        access_token,
                        refresh_token,
                        context.state.clone(),
                    ),
                ))
                .finish())
        }
        _ => Ok(HttpResponse::Ok().json(json!({
            "accessToken": access_token,
            "refreshToken": refresh_token,
        }))),
    }
}

async fn get_encryption_key_from_fulldid_key_uri(
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

async fn get_w3n(
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
