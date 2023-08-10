use actix_session::Session;
use actix_web::{get, post, web, HttpResponse, Responder};

use rand::Rng;
use serde::{Deserialize, Serialize};

use sodiumoxide::crypto::box_;

use crate::AppState;

// Data that the user receives when starting a session
#[derive(Clone, Debug, Serialize, Deserialize)]
struct ChallengeData {
    #[serde(rename = "dAppName")]
    app_name: String,
    #[serde(rename = "dAppEncryptionKeyUri")]
    encryption_key_uri: String,
    challenge: String,
}

impl ChallengeData {
    fn new(app_name: &str, encryption_key_uri: &str) -> Self {
        let mut rng = rand::thread_rng();
        let challenge: [u8; 32] = rng.gen();
        let challenge_hex = format!("0x{}", hex::encode(challenge));
        Self {
            app_name: app_name.to_string(),
            encryption_key_uri: encryption_key_uri.to_string(),
            challenge: challenge_hex,
        }
    }
}

// Data that the user passes back to us when starting a session
#[derive(Clone, Debug, Serialize, Deserialize)]
struct ChallengeResponse {
    #[serde(rename = "encryptionKeyUri")]
    encryption_key_uri: String,
    #[serde(rename = "encryptedChallenge")]
    encrypted_challenge: String,
    nonce: String,
}

// GET /api/v1/challenge -> create a new challenge, store it in the cookies and send it to the user
#[get("/api/v1/challenge")]
async fn challenge_handler(session: Session, app_state: web::Data<AppState>) -> impl Responder {
    log::info!("GET challenge handler");
    let challenge_data = ChallengeData::new(&app_state.app_name, &app_state.encryption_key_uri);
    session.insert("challenge", challenge_data.clone()).unwrap();
    HttpResponse::Ok().json(challenge_data)
}

// POST /api/v1/challenge -> check the challenge response and start a session
#[post("/api/v1/challenge")]
async fn challenge_response_handler(
    session: Session,
    app_state: web::Data<AppState>,
    challenge_response: web::Json<ChallengeResponse>,
) -> impl Responder {
    log::info!("POST challenge handler");
    let session_challenge = match session.get::<ChallengeData>("challenge") {
        Ok(Some(data)) => data.challenge,
        Ok(None) => return HttpResponse::Unauthorized().body("No session"),
        Err(err) => return HttpResponse::Unauthorized().body(format!("Error: {err}")),
    };
    let session_challenge_bytes = match hex::decode(session_challenge.trim_start_matches("0x")) {
        Ok(bytes) => bytes,
        _ => return HttpResponse::Unauthorized().body("Invalid challenge"),
    };
    let nonce = match hex::decode(challenge_response.nonce.trim_start_matches("0x")) {
        Ok(nonce) => nonce,
        _ => return HttpResponse::Unauthorized().body("Invalid nonce"),
    };
    let encrypted_challenge = match hex::decode(
        challenge_response
            .encrypted_challenge
            .trim_start_matches("0x"),
    ) {
        Ok(encrypted_challenge) => encrypted_challenge,
        _ => return HttpResponse::Unauthorized().body("Invalid encrypted challenge"),
    };
    let others_pubkey = match crate::util::parse_encryption_key_from_lightdid(
        challenge_response.encryption_key_uri.as_str(),
    ) {
        Ok(key) => key,
        _ => return HttpResponse::Unauthorized().body("Invalid encryption key"),
    };
    let our_secretkey = app_state.secret_key.clone();
    let nonce = box_::Nonce::from_slice(&nonce).unwrap();
    let pk = box_::PublicKey::from_slice(&others_pubkey).unwrap();
    let sk = box_::SecretKey::from_slice(&our_secretkey).unwrap();
    let decrypted_challenge = match box_::open(&encrypted_challenge, &nonce, &pk, &sk) {
        Ok(decrypted_challenge) => decrypted_challenge,
        _ => return HttpResponse::Unauthorized().body("Could not decrypt challenge"),
    };

    if session_challenge_bytes == decrypted_challenge {
        session
            .insert("key_uri", challenge_response.encryption_key_uri.clone())
            .unwrap();
        HttpResponse::Ok().body("Challenge accepted")
    } else {
        HttpResponse::Unauthorized().body("Wrong challenge")
    }
}
