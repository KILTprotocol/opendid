use actix_session::Session;
use actix_web::{post, web, HttpResponse};
use sha2::{Sha512, Digest};
use sp_runtime::traits::Verify;
use base64::{Engine, engine::general_purpose};
use std::sync::RwLock;
use subxt::ext::codec::{Decode, IoReader};

use crate::{
    constants::OIDC_SESSION_KEY,
    kilt::{
        self, get_did_doc,
        runtime_types::did::did_details::{DidPublicKey, DidVerificationKey},
    },
    routes::error::Error,
    verify::{hex_decode, hex_encode},
    AppState, AuthorizeQueryParameters
};


#[derive(serde::Deserialize)]
#[allow(dead_code)]
struct JWTHeader {
    alg: String,
    typ: String,
    #[serde(rename = "keyURI")]
    pub key_uri: String,

}

#[derive(serde::Deserialize)]
#[allow(dead_code)]
struct JWTPayload {
    
    pub iss: String,
    pub sub: String,
    
}



#[post("/api/v1/did/{token}")]
async fn post_did_handler(
    app_state: web::Data<RwLock<AppState>>,
    session: Session,
    path: web::Path<String>,
) -> Result<HttpResponse, Error> {
    log::info!("POST DID handler");

    let jwt_token = path.into_inner();

    // get requirements for this client, the client id comes from the session
    let oidc_context = session
        .get::<AuthorizeQueryParameters>(OIDC_SESSION_KEY)
        .map_err(|_| Error::OauthNoSession)?
        .ok_or(Error::OauthInvalidClientId)?;

    let nonce = oidc_context.nonce;

    let mut hasher =  Sha512::new();

    let parts : Vec<&str> = jwt_token.split('.').collect();
    let header = parts[0];
    let body = parts[1];
    let signature = parts[2];

    hasher.update(format!("{}.{}", header, body));
    let data_to_verify_hex = hex_encode(hasher.finalize());
    let data_to_verify = data_to_verify_hex.trim_start_matches("0x").as_bytes();

    let decoded_header = general_purpose::STANDARD.decode(header).map_err(|_|  Error::VerifyJWT)?;
    let decoded_body = general_purpose::STANDARD.decode(body).map_err(|_|  Error::VerifyJWT)?;
    let decoded_signature = general_purpose::STANDARD.decode(signature).map_err(|_|  Error::VerifyJWT)?;

    let jwt_header: JWTHeader = serde_json::from_slice(&decoded_header).map_err(|_|  Error::VerifyJWT)?;
    let jwt_payload: JWTPayload = serde_json::from_slice(&decoded_body).map_err(|_|  Error::VerifyJWT)?;

    let sender = &jwt_payload.iss;

    let endpoint = {
        let app_state = app_state.read()?;
        app_state.kilt_endpoint.clone()
    };
    let cli = kilt::connect(&endpoint)
        .await
        .map_err(|_| Error::CantConnectToBlockchain)?;

    let did_document = get_did_doc(sender, &cli).await?;

    let signed_key = hex_decode(jwt_header.key_uri.trim_start_matches("0x"))
        .map_err(|_| Error::InvalidDidSignature)?;

    let (_, target_key) = did_document
        .public_keys
        .0
        .iter()
        .find(|(key, _)| key.as_bytes() == signed_key)
        .ok_or(Error::InvalidDidSignature)?;

    let public_key = match &target_key.key {
        DidPublicKey::PublicVerificationKey(DidVerificationKey::Sr25519(pk)) => {
            Ok(sp_runtime::AccountId32::from(pk.0))
        }
        DidPublicKey::PublicVerificationKey(DidVerificationKey::Ed25519(pk)) => {
            Ok(sp_runtime::AccountId32::from(pk.0))
        }
        _ => Err(Error::InvalidDidSignature),
    }?;


    let signature_string = String::from_utf8(decoded_signature).map_err(|_| Error::VerifyJWT)?;
    let trimed_signature = hex_decode(signature_string.trim_start_matches("0x")).map_err(|_| Error::VerifyJWT)?;

    let valid = {
        if let Ok(signature) =
            sp_runtime::MultiSignature::decode(&mut IoReader(trimed_signature.as_slice()))
        {
            signature.verify(data_to_verify, &public_key)
        } else if let Ok(signature) =
            sp_core::sr25519::Signature::decode(&mut IoReader(trimed_signature.as_slice() ))
        {
            signature.verify(
                data_to_verify,
                &sp_core::sr25519::Public(public_key.into()),
            )
        } else if let Ok(signature) =
            sp_core::ed25519::Signature::decode(&mut IoReader(trimed_signature.as_slice()))
        {
            signature.verify(
                data_to_verify,
                &sp_core::ed25519::Public(public_key.into()),
            )
        } else {
            false
        }
    };

    if !valid {
        return Err(Error::InvalidDidSignature);
    }

    let w3n = kilt::get_w3n(&jwt_payload.iss, &cli).await.unwrap_or("".into());
    let props = serde_json::Map::new();

    //construct id_token and refresh_token

    let mut app_state = app_state.write()?; // may update the rhai checkers
    let id_token = app_state
        .jwt_builder
        .new_id_token(sender, &w3n, &props, &Some(nonce.clone()))
        .to_jwt(&app_state.jwt_secret_key, &app_state.jwt_algorithm)
        .map_err(|e| {
            log::error!("Failed to create id token: {}", e);
            Error::CreateJWT
        })?;

    let refresh_token = app_state
        .jwt_builder
        .new_refresh_token(sender, &w3n, &props, &Some(nonce.clone()))
        .to_jwt(&app_state.jwt_secret_key, &app_state.jwt_algorithm)
        .map_err(|e| {
            log::error!("Failed to create refresh token: {}", e);
            Error::CreateJWT
        })?;

    // check if there are any additional scripting checks to be done
    let client_configs = app_state.client_configs.clone();
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
