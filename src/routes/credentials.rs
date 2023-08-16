use std::{collections::HashMap};

use actix_session::Session;
use actix_web::{get, post, web, HttpResponse, Responder};
use serde::{Deserialize, Serialize};
use serde_json::json;
use sodiumoxide::crypto::box_;
use sp_core::{crypto::Ss58Codec, H256};

use subxt::OnlineClient;

use crate::{
    config::CredentialRequirement,
    kilt::{
        self,
        runtime_types::{
            did::did_details::{DidEncryptionKey, DidPublicKey},
        },
        KiltConfig,
    },
    messages::{EncryptedMessage, Message, MessageBody},
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
) -> impl Responder {
    log::info!("GET credential requirements handler");
    let key_uri = match session.get::<String>("key_uri") {
        Ok(Some(data)) => data,
        _ => return HttpResponse::Unauthorized().body("No session"),
    };
    let challenge = format!("0x{}", hex::encode(box_::gen_nonce()));
    match session.insert("credential-challenge", &challenge) {
        Ok(_) => (),
        _ => return HttpResponse::Unauthorized().body("Could not store challenge"),
    };
    let sender = app_state.encryption_key_uri.split('#').collect::<Vec<&str>>()[0];
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
    let others_pubkey = match parse_encryption_key_from_lightdid(key_uri.as_str()) {
        Ok(key) => key,
        _ => return HttpResponse::Unauthorized().body("Invalid encryption key"),
    };
    let nonce = box_::gen_nonce();
    let pk = box_::PublicKey::from_slice(&others_pubkey).unwrap();
    let sk = box_::SecretKey::from_slice(&our_secretkey).unwrap();
    let encrypted_msg = box_::seal(msg_bytes, &nonce, &pk, &sk);
    let encrypted_msg_hex = format!("0x{}", hex::encode(encrypted_msg));
    let nonce_hex = format!("0x{}", hex::encode(nonce));
    let response = EncryptedMessage {
        cipher_text: encrypted_msg_hex,
        nonce: nonce_hex,
        sender_key_uri: app_state.encryption_key_uri.clone(),
        receiver_key_uri: key_uri,
    };
    HttpResponse::Ok().json(response)
}

#[post("/api/v1/credentials")]
async fn post_credential_handler(
    app_state: web::Data<AppState>,
    session: Session,
    body: web::Json<EncryptedMessage>,
    query: web::Query<PostCredentialQueryParameter>,
) -> impl Responder {
    log::info!("POST credential handler");
    log::info!("body: {:?}", body);

    let cli = match kilt::connect("spiritnet").await {
        Ok(cli) => cli,
        _ => return HttpResponse::InternalServerError().body("Could not connect to KILT"),
    };

    let pk = match get_encryption_key_from_fulldid_key_uri(&body.sender_key_uri, &cli).await {
        Ok(pk) => pk,
        _ => return HttpResponse::BadRequest().body("Could not get encryption key"),
    };

    let nonce = match hex::decode(body.nonce.trim_start_matches("0x")) {
        Ok(nonce) => box_::Nonce::from_slice(&nonce).unwrap(),
        _ => return HttpResponse::BadRequest().body("Could not decode nonce"),
    };

    let cipher_text = match hex::decode(body.cipher_text.trim_start_matches("0x")) {
        Ok(cipher_text) => cipher_text,
        _ => return HttpResponse::BadRequest().body("Could not decode cipher text"),
    };

    let sk = box_::SecretKey::from_slice(&app_state.secret_key).unwrap();

    let decrypted_msg = match box_::open(&cipher_text, &nonce, &pk, &sk) {
        Ok(decrypted_msg) => decrypted_msg,
        _ => return HttpResponse::BadRequest().body("Could not decrypt message"),
    };

    { // Logging stuff
        let data: serde_json::Value = serde_json::from_slice(&decrypted_msg).unwrap();
        log::info!("Decrypted message: {:?}", data);

    }
    let content: Message<Vec<SubmitCredentialMessageBodyContent>> =
        match serde_json::from_slice(&decrypted_msg) {
            Ok(content) => content,
            Err(err) => {
                return HttpResponse::BadRequest().body(format!("Could not parse message {err:?}"))
            }
        };

    let challenge = match session.get::<String>("credential-challenge") {
        Ok(Some(data)) => match hex::decode(data.trim_start_matches("0x")) {
            Ok(data) => data,
            _ => return HttpResponse::Unauthorized().body("Could not decode challenge"),
        },
        _ => return HttpResponse::Unauthorized().body("No session"),
    };

    // check internal integrity of the credential and look it up on chain
    let attestations = match verify_credential_message(&content, challenge, &cli).await {
        Ok(a) => a,
        Err(err) => {
            return HttpResponse::BadRequest().body(format!("Could not verify message {err:?}"))
        }
    };

    // go through all credential requirements and check that at least one is fulfilled with the given cred
    let mut fulfilled = false;
    let mut props = serde_json::Map::new();
    
    for i in 0..attestations.len() {
        let attestation = &attestations[i];
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
                _ => return HttpResponse::BadRequest().body("Could not get claim contents"),
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
        return HttpResponse::BadRequest().body("No credential requirement fulfilled");
    }

    log::info!("Credential checked, all good to go");
    let access_token = match app_state
        .token_builder
        .new_access_token(&content.sender, &props)
        .to_jwt(&app_state.token_secret)
    {
        Ok(data) => data,
        _ => return HttpResponse::InternalServerError().body("Could not create access token"),
    };

    let refresh_token = match app_state
        .token_builder
        .new_refresh_token(&content.sender, &props)
        .to_jwt(&app_state.token_secret)
    {
        Ok(data) => data,
        _ => return HttpResponse::InternalServerError().body("Could not create refresh token"),
    };

    if let Some(redirect_url) = &query.redirect {
        return HttpResponse::Found()
            .append_header((
                "Location", 
                format!("{}?access_token={}&refresh_token={}",redirect_url, access_token, refresh_token)
            )).finish();
    }

    HttpResponse::Ok().json(json!({
        "accessToken": access_token,
        "refreshToken": refresh_token,
    }))
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
