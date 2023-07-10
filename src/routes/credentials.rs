use std::{collections::HashMap, str::FromStr};

use actix_session::Session;
use actix_web::{web, get, Responder, HttpResponse, post};
use serde::{Serialize, Deserialize};
use serde_json::json;
use sodiumoxide::crypto::box_;
use sp_core::{Decode, crypto::Ss58Codec, H256};
use sp_runtime::{codec::IoReader, traits::Verify, AccountId32};
use subxt::OnlineClient;

use crate::{config::CredentialRequirement, AppState, messages::{Message, MessageBody, EncryptedMessage}, util::parse_encryption_key_from_lightdid, kilt::{self, KiltConfig, runtime_types::{did::did_details::{DidPublicKey, DidEncryptionKey, DidVerificationKey}, attestation::attestations::AttestationDetails}}};

#[derive(Clone, Debug, Serialize, Deserialize)]
struct RequestCredentialMessageBodyContent {
    #[serde(rename = "cTypes")]
    ctypes: Vec<CredentialRequirement>,
    challenge: String,
}


#[derive(Clone, Debug, Serialize, Deserialize)]
struct SubmitCredentialMessageBodyContent {
    claim: Claim,
    #[serde(rename = "claimNonceMap")]
    claim_nonce_map: HashMap<String, String>,
    #[serde(rename = "claimHashes")]
    claim_hashes: Vec<String>,
    #[serde(rename = "delegationId")]
    delegation_id: Option<String>,
    legitimations: Vec<serde_json::Value>,
    #[serde(rename = "claimerSignature")]
    claimer_signature: DidSignature,
    #[serde(rename = "rootHash")]
    root_hash: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct Claim {
    #[serde(rename = "cTypeHash")]
    ctype_id: String,
    contents: serde_json::Value,
    owner: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct DidSignature {
    #[serde(rename = "keyId")]
    key_id: String,
    signature: String,
}


#[get("/api/v1/credentials")]
async fn get_credential_requirements_handler(app_state: web::Data<AppState>, session: Session) -> impl Responder {
    log::info!("GET credential requirements handler");
    let key_uri = match session.get::<String>("key_uri") {
        Ok(Some(data)) => data,
        _ => return HttpResponse::Unauthorized().body("No session"),
    };
    let challenge = format!("0x{}", hex::encode(box_::gen_nonce()));
    match session.insert("credential-challenge", &challenge){
        Ok(_) => (),
        _ => return HttpResponse::Unauthorized().body("Could not store challenge"),
    };
    let msg = Message {
        body: MessageBody {
            type_: "request-credential".to_string(),
            content: RequestCredentialMessageBodyContent {
                ctypes: app_state.credential_requirements.clone(),
                challenge,
            },
        },
        created_at: 0,
        sender: app_state.encryption_key_uri.clone(),
        receiver: key_uri.clone(),
        message_id: uuid::Uuid::new_v4().to_string(),
        in_reply_to: "".to_string(),
        references: vec![],
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
        receiver_key_uri: key_uri.clone(),
    };
    HttpResponse::Ok().json(response)
}

#[post("/api/v1/credentials")]
async fn post_credential_handler(app_state: web::Data<AppState>, session: Session, body: web::Json<EncryptedMessage>) -> impl Responder {
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

    let nonce = match hex::decode(&body.nonce.trim_start_matches("0x")) {
        Ok(nonce) => box_::Nonce::from_slice(&nonce).unwrap(),
        _ => return HttpResponse::BadRequest().body("Could not decode nonce"),
    };

    let cipher_text = match hex::decode(&body.cipher_text.trim_start_matches("0x")) {
        Ok(cipher_text) => cipher_text,
        _ => return HttpResponse::BadRequest().body("Could not decode cipher text"),
    };

    let sk = box_::SecretKey::from_slice(&app_state.secret_key).unwrap();

    let decrypted_msg = match box_::open(&cipher_text, &nonce, &pk, &sk) {
        Ok(decrypted_msg) => decrypted_msg,
        _ => return HttpResponse::BadRequest().body("Could not decrypt message"),
    };
    
    let content: Message<SubmitCredentialMessageBodyContent> = match serde_json::from_slice(&decrypted_msg) {
        Ok(content) => content,
        Err(err) => return HttpResponse::BadRequest().body(format!("Could not parse message {:?}", err)),
    };
    
    let challenge = match session.get::<String>("credential-challenge") {
        Ok(Some(data)) => match hex::decode(data.trim_start_matches("0x")){
            Ok(data) => data,
            _ => return HttpResponse::Unauthorized().body("Could not decode challenge"),
        },
        _ => return HttpResponse::Unauthorized().body("No session"),
    };

    let root_hash = match hex::decode(&content.body.content.root_hash.trim_start_matches("0x")){
        Ok(data) => data,
        _ => return HttpResponse::BadRequest().body("Could not decode root hash"),
    };

    // verify claimer signature
    let signature_data = [root_hash, challenge].concat();
    let signature = match hex::decode(content.body.content.claimer_signature.signature.trim_start_matches("0x")){
        Ok(data) => match sp_runtime::MultiSignature::decode(&mut IoReader(data.as_slice())) {
            Ok(data) => data,
            _ => return HttpResponse::BadRequest().body("Could not decode signature"),
        },
        _ => return HttpResponse::BadRequest().body("Could not decode signature"),
    };
    let signer = match get_auth_pubkey(&content.sender, &cli).await {
        Ok(data) => data,
        _ => return HttpResponse::BadRequest().body("Could not get auth pubkey"),
    };
    if !signature.verify(signature_data.as_slice(), &signer) {
        return HttpResponse::BadRequest().body("Could not verify signature");
    }
    log::info!("Claimer signature verified");

    // lookup credential root hash
    let attestation = match get_attestation(&content.body.content.root_hash, &cli).await {
        Ok(data) => data,
        _ => return HttpResponse::BadRequest().body("Could not get attestation"),
    };
    log::info!("Attestation found on chain: {:?}", attestation);

    // check if it is  not revoked
    if attestation.revoked {
        return HttpResponse::BadRequest().body("Attestation is revoked");
    }
    log::info!("Attestation not revoked");

    // go through all credential requirements and check that at least one is fulfilled with the given cred
    let mut fulfilled = false;
    let credential_attester_did = format!("did:kilt:{}",
        sp_runtime::AccountId32::from(attestation.attester.0)
        .to_ss58check_with_version(38u16.into())
    );
    for requirement in &app_state.credential_requirements {
        if requirement.ctype_hash != content.body.content.claim.ctype_id {
            log::info!("Requirement ctype hash does not match");
            continue;
        }
        if ! requirement.trusted_attesters.contains(&credential_attester_did) {
            log::info!("Requirement attester DID does not match");
            continue;
        }
        // go through all required properties and check they are in the attestation
        let mut properties_fulfilled = true;
        let content_object = match content.body.content.claim.contents.as_object() {
            Some(data) => data,
            _ => return HttpResponse::BadRequest().body("Could not get claim contents"),
        };
        for property in &requirement.required_properties {
            if ! content_object.contains_key(property) {
                log::info!("Requirement property '{}' not found", property);
                properties_fulfilled = false;
                break;
            }
        }
        if ! properties_fulfilled {
            log::info!("Requirement properties not fulfilled");
            continue;
        }
        log::info!("Requirement fulfilled");
        fulfilled = true;
        break;
    }

    if !fulfilled {
        log::info!("No credential requirement fulfilled");
        return HttpResponse::BadRequest().body("No credential requirement fulfilled");
    }

    log::info!("Credential checked, all good to go");

    HttpResponse::Ok().json(json!({
        "status": "ok",
    }))
}


async fn get_encryption_key_from_fulldid_key_uri(key_uri: &str, cli: &OnlineClient<KiltConfig>) -> Result<box_::PublicKey, Box<dyn std::error::Error>> {
    let key_uri_parts: Vec<&str> = key_uri.split("#").collect();
    if key_uri_parts.len() != 2 {
        return Err("Invalid sender key URI".into());
    }
    let did = key_uri_parts[0].to_string();
    let key_id = key_uri_parts[1].to_string();
    let kid_bs: [u8; 32] = hex::decode(&key_id.trim_start_matches("0x"))?.try_into().map_err(|_| "malformed key id")?;
    let kid = H256::from(kid_bs);
    let doc = get_did_doc(&did, cli).await?;
    match doc.public_keys.0.iter().find(|&(k,v)| *k == kid) {
        Some((_, details)) => {
            let pk = match details.key {
                DidPublicKey::PublicEncryptionKey(DidEncryptionKey::X25519(pk)) => pk,
                _ => return Err("Invalid sender public key".into()),
            };
            box_::PublicKey::from_slice(&pk).ok_or("Invalid sender public key".into())
        }
        _ => return Err("Could not get sender public key".into()),
    }
}

async fn get_auth_pubkey(did: &str, cli: &OnlineClient<KiltConfig>) -> Result<sp_runtime::AccountId32, Box<dyn std::error::Error>> {
    let doc = get_did_doc(did, cli).await?;
    let auth_key_id = doc.authentication_key;
    let pubkey_details = &doc.public_keys.0.iter()
        .find(|&(k,v)| *k == auth_key_id)
        .ok_or("Could not get auth key")?.1;
    match &pubkey_details.key {
        DidPublicKey::PublicVerificationKey(DidVerificationKey::Sr25519(pk)) => Ok(sp_runtime::AccountId32::from(pk.0)),
        DidPublicKey::PublicVerificationKey(DidVerificationKey::Ed25519(pk)) => Ok(sp_runtime::AccountId32::from(pk.0)),
        _ => return Err("Invalid auth key".into()),
    }
}

async fn get_did_doc(did: &str, cli: &OnlineClient<KiltConfig>) -> Result<kilt::runtime_types::did::did_details::DidDetails, Box<dyn std::error::Error>> {
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

async fn get_attestation(hash: &str, cli: &OnlineClient<KiltConfig>) -> Result<AttestationDetails, Box<dyn std::error::Error>> {
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
