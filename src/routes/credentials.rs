use std::{collections::HashMap, sync::RwLock};

use actix_session::Session;
use actix_web::{get, post, web, HttpResponse};
use serde::{Deserialize, Serialize};

use sodiumoxide::crypto::box_;
use sp_core::crypto::Ss58Codec;

use crate::{
    config::CredentialRequirement,
    constants::OIDC_SESSION_KEY,
    kilt::{self, parse_encryption_key_from_lightdid},
    messages::{EncryptedMessage, Message, MessageBody},
    routes::{error::Error, AuthorizeQueryParameters},
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
    app_state: web::Data<RwLock<AppState>>,
    session: Session,
) -> Result<HttpResponse, Error> {
    log::info!("GET credential requirements handler");
    let app_state = app_state.read()?;

    // create a challenge and store it in the session
    let key_uri = session.get::<String>("key_uri")?.ok_or(Error::SessionGet)?;
    let challenge = format!("0x{}", hex::encode(box_::gen_nonce()));
    session.insert("credential-challenge", challenge.clone())?;

    // get sender DID for the response from local encryption key URI
    let sender = app_state
        .encryption_key_uri
        .split('#')
        .collect::<Vec<&str>>()
        .first()
        .ok_or(Error::InvalidPrivateKey)?
        .to_owned();

    // get the credential requirements for this specific client. The client ID comes from the session
    let oidc_context = session
        .get::<AuthorizeQueryParameters>(OIDC_SESSION_KEY)
        .map_err(|_| Error::OauthNoSession)?
        .ok_or(Error::OauthInvalidClientId)?;
    let requirements = &app_state
        .client_configs
        .get(&oidc_context.client_id)
        .ok_or(Error::OauthInvalidClientId)?
        .requirements;

    // construct response message
    let msg = Message {
        body: MessageBody {
            type_: "request-credential".to_string(),
            content: RequestCredentialMessageBodyContent {
                ctypes: requirements.clone(),
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

    // encode and encrypt it for the receiver
    let msg_json = serde_json::to_string(&msg).unwrap();
    let msg_bytes = msg_json.as_bytes();
    let our_secretkey = app_state.session_secret_key.clone();
    let others_pubkey = parse_encryption_key_from_lightdid(key_uri.as_str())?;
    let nonce = box_::gen_nonce();
    let sk = box_::SecretKey::from_slice(&our_secretkey).ok_or(Error::InvalidPrivateKey)?;
    let encrypted_msg = box_::seal(msg_bytes, &nonce, &others_pubkey, &sk);
    let response = EncryptedMessage {
        cipher_text: encrypted_msg,
        nonce: nonce[..].into(),
        sender_key_uri: app_state.encryption_key_uri.clone(),
        receiver_key_uri: key_uri,
    };

    // send it back
    Ok(HttpResponse::Ok().json(response))
}

#[post("/api/v1/credentials")]
async fn post_credential_handler(
    app_state: web::Data<RwLock<AppState>>,
    session: Session,
    body: web::Json<EncryptedMessage>,
) -> Result<HttpResponse, Error> {
    log::info!("POST credential handler");
    let endpoint = {
        let app_state = app_state.read()?;
        app_state.kilt_endpoint.clone()
    };
    let cli = kilt::connect(&endpoint)
        .await
        .map_err(|_| Error::CantConnectToBlockchain)?;

    // get the sender's public key from the encryption key URI
    let pk = kilt::get_encryption_key_from_fulldid_key_uri(&body.sender_key_uri, &cli).await?;

    // decrypt the message
    let nonce = box_::Nonce::from_slice(&body.nonce).ok_or(Error::InvalidNonce)?;
    let secret_key = {
        let app_state = app_state.read()?;
        app_state.session_secret_key.clone()
    };
    let sk = box_::SecretKey::from_slice(&secret_key).ok_or(Error::InvalidPrivateKey)?;
    let decrypted_msg =
        box_::open(&body.cipher_text, &nonce, &pk, &sk).map_err(|_| Error::FailedToDecrypt)?;
    let content: Message<Vec<SubmitCredentialMessageBodyContent>> =
        serde_json::from_slice(&decrypted_msg).map_err(|_| Error::FailedToParseMessage)?;

    // get the challenge from the session
    let challenge_hex = session
        .get::<String>("credential-challenge")?
        .ok_or(Error::GetChallenge)?;
    let challenge =
        hex::decode(challenge_hex.trim_start_matches("0x")).map_err(|_| Error::GetChallenge)?;

    // verify the credential message
    let attestations = verify_credential_message(&content, challenge, &cli)
        .await
        .map_err(|e| Error::VerifyCredential(format!("{}", e)))?;

    // get credential requirements for this client, the client id comes from the session
    let oidc_context = session
        .get::<AuthorizeQueryParameters>(OIDC_SESSION_KEY)
        .map_err(|_| Error::OauthNoSession)?
        .ok_or(Error::OauthInvalidClientId)?;
    let client_configs = {
        let app_state = app_state.read()?;
        app_state.client_configs.clone()
    };
    let requirements = &client_configs
        .get(&oidc_context.client_id)
        .ok_or(Error::OauthInvalidClientId)?
        .requirements;

    // go through all credential requirements and check that at least one is fulfilled with the given cred
    let mut fulfilled = false;
    let mut props = serde_json::Map::new();
    for (i, attestation) in attestations.iter().enumerate() {
        let content = &content.body.content.get(i).ok_or(Error::VerifyCredential(
            "Could not get content from message".into(),
        ))?;
        let credential_attester_did = format!(
            "did:kilt:{}",
            sp_runtime::AccountId32::from(attestation.attester.0)
                .to_ss58check_with_version(kilt::SS58_PREFIX.into())
        );
        for requirement in requirements {
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
            let mut properties_fulfilled = true;
            let content_object =
                content
                    .claim
                    .contents
                    .as_object()
                    .ok_or(Error::VerifyCredential(
                        "Could not get claim contents".into(),
                    ))?;

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

    // if no requirement is fulfilled, return an error
    if !fulfilled {
        log::info!("No credential requirement fulfilled");
        return Err(Error::VerifyCredential(
            "No credential requirement fulfilled".into(),
        ));
    }

    log::info!("Credential checked, all good to go");

    // get the web3 name for the senders DID
    let w3n = kilt::get_w3n(&content.sender, &cli)
        .await
        .unwrap_or("".into());

    // construct id_token and refresh_token
    let nonce = Some(oidc_context.nonce.clone());
    let mut app_state = app_state.write()?; // may update the rhai checkers
    let id_token = app_state
        .jwt_builder
        .new_id_token(&content.sender, &w3n, &props, &nonce)
        .to_jwt(&app_state.jwt_secret_key, &app_state.jwt_algorithm)
        .map_err(|e| {
            log::error!("Failed to create id token: {}", e);
            Error::CreateJWT
        })?;

    let refresh_token = app_state
        .jwt_builder
        .new_refresh_token(&content.sender, &w3n, &props, &nonce)
        .to_jwt(&app_state.jwt_secret_key, &app_state.jwt_algorithm)
        .map_err(|e| {
            log::error!("Failed to create refresh token: {}", e);
            Error::CreateJWT
        })?;

    // check if there are any additional scripting checks to be done
    let client_config = client_configs
        .get(&oidc_context.client_id)
        .ok_or(Error::OauthInvalidClientId)?;
    if let Some(checks_directory) = &client_config.checks_directory {
        let checker = app_state
            .rhai_checkers
            .get_or_create(&oidc_context.client_id, checks_directory)?;
        checker.check(&id_token)?;
    }

    // return the response as a HTTP NoContent, to give the frontend a chance to do the redirect on its own
    Ok(HttpResponse::NoContent()
        .append_header((
            "Location",
            format!(
                "{}#id_token={}&refresh_token={}&state={}&token_type=bearer",
                oidc_context.redirect_uri.clone(),
                id_token,
                refresh_token,
                oidc_context.state.clone(),
            ),
        ))
        .finish())
}
