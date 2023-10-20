use std::sync::RwLock;

use actix_session::Session;
use actix_web::{get, post, web, HttpResponse};

use rand::Rng;
use serde::{Deserialize, Serialize};

use sodiumoxide::crypto::box_;

use crate::{
    routes::error::Error,
    serialize::{hex_nonce, prefixed_hex},
    AppState,
};

/// Data that the user receives when starting a session
#[derive(Clone, Debug, Serialize, Deserialize)]
struct ChallengeData {
    #[serde(rename = "dAppName")]
    app_name: String,
    #[serde(rename = "dAppEncryptionKeyUri")]
    encryption_key_uri: String,
    #[serde(with = "prefixed_hex")]
    challenge: Vec<u8>,
}

impl ChallengeData {
    fn new(app_name: &str, encryption_key_uri: &str) -> Self {
        let mut rng = rand::thread_rng();
        let challenge: [u8; 32] = rng.gen();
        Self {
            app_name: app_name.to_string(),
            encryption_key_uri: encryption_key_uri.to_string(),
            challenge: challenge.to_vec(),
        }
    }
}

/// Data that the user passes back to us when starting a session
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct ChallengeResponse {
    encryption_key_uri: String,
    #[serde(with = "prefixed_hex")]
    encrypted_challenge: Vec<u8>,
    #[serde(with = "hex_nonce")]
    nonce: box_::Nonce,
}

/// GET /api/v1/challenge -> create a new challenge, store it in the cookies and send it to the user
#[get("/api/v1/challenge")]
async fn challenge_handler(
    session: Session,
    app_state: web::Data<RwLock<AppState>>,
) -> Result<HttpResponse, Error> {
    log::info!("GET challenge handler");
    let app_state = app_state.read()?;
    let challenge_data = ChallengeData::new(&app_state.app_name, &app_state.encryption_key_uri);
    session.insert("challenge", challenge_data.clone())?;
    Ok(HttpResponse::Ok().json(challenge_data))
}

/// POST /api/v1/challenge -> check the challenge response and start a session
#[post("/api/v1/challenge")]
async fn challenge_response_handler(
    session: Session,
    app_state: web::Data<RwLock<AppState>>,
    challenge_response: web::Json<ChallengeResponse>,
) -> Result<HttpResponse, Error> {
    log::info!("POST challenge handler");
    let app_state = app_state.read()?;
    let session_challenge_bytes = session
        .get::<ChallengeData>("challenge")?
        .ok_or(Error::SessionGet)?
        .challenge;

    let others_pubkey = crate::kilt::parse_encryption_key_from_lightdid(
        challenge_response.encryption_key_uri.as_str(),
    )?;

    let our_secretkey = box_::SecretKey::from_slice(&app_state.session_secret_key)
        .ok_or(Error::InvalidPrivateKey)?;

    let decrypted_challenge = box_::open(
        &challenge_response.encrypted_challenge,
        &challenge_response.nonce,
        &others_pubkey,
        &our_secretkey,
    )
    .map_err(|_| Error::InvalidChallenge("Unable to decrypt"))?;

    if session_challenge_bytes == decrypted_challenge {
        session
            .insert("key_uri", challenge_response.encryption_key_uri.clone())
            .map_err(|_| Error::SessionInsert)?;
        Ok(HttpResponse::Ok().body("Challenge accepted"))
    } else {
        Err(Error::InvalidChallenge("Challenge doesn't match"))
    }
}
