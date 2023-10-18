use actix_session::Session;
use actix_web::{post, web, HttpResponse};
use hmac::{Hmac, Mac};
use jwt::VerifyWithKey;
use sha2::Sha256;
use sp_runtime::traits::Verify;
use std::sync::RwLock;
use subxt::ext::codec::{Decode, IoReader};

use crate::{
    constants::OIDC_SESSION_KEY,
    kilt::{
        self, get_did_doc,
        runtime_types::did::did_details::{DidPublicKey, DidVerificationKey},
    },
    routes::error::Error,
    verify::hex_decode,
    AppState, AuthorizeQueryParameters,
};

#[derive(serde::Deserialize)]
struct JWTPayload {
    pub signature: String,
    #[serde(rename = "keyURI")]
    pub key_uri: String,
    pub iss: String,
    pub sub: String,
    pub exp: i64,
}

impl JWTPayload {
    pub fn check_is_expired(&self) -> Result<(), Error> {
        let now = chrono::Utc::now().timestamp();
        if self.exp < now {
            return Err(Error::VerifyJWT);
        }
        Ok(())
    }

    pub fn check_iss_and_sub(&self) -> Result<(), Error> {
        if self.iss != self.sub {
            return Err(Error::VerifyJWT);
        }
        Ok(())
    }
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

    let secret: Hmac<Sha256> =
        Hmac::new_from_slice(nonce.as_bytes()).map_err(|_| Error::VerifyJWT)?;

    let payload: JWTPayload = jwt_token
        .verify_with_key(&secret)
        .map_err(|_| Error::VerifyJWT)?;

    payload.check_is_expired()?;
    payload.check_iss_and_sub()?;

    let sender = &payload.iss;

    let endpoint = {
        let app_state = app_state.read()?;
        app_state.kilt_endpoint.clone()
    };
    let cli = kilt::connect(&endpoint)
        .await
        .map_err(|_| Error::CantConnectToBlockchain)?;

    let did_document = get_did_doc(&sender, &cli).await?;

    let signed_key = hex_decode(payload.key_uri.trim_start_matches("0x"))
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

    // Check the signature
    let signature = hex_decode(payload.signature.trim_start_matches("0x"))
        .map_err(|_| Error::InvalidDidSignature)?;

    let valid = {
        if let Ok(signature) =
            sp_runtime::MultiSignature::decode(&mut IoReader(signature.as_slice()))
        {
            signature.verify(nonce.as_bytes(), &public_key)
        } else if let Ok(signature) =
            sp_core::sr25519::Signature::decode(&mut IoReader(signature.as_slice()))
        {
            signature.verify(
                nonce.as_bytes(),
                &sp_core::sr25519::Public(public_key.into()),
            )
        } else if let Ok(signature) =
            sp_core::ed25519::Signature::decode(&mut IoReader(signature.as_slice()))
        {
            signature.verify(
                nonce.as_bytes(),
                &sp_core::ed25519::Public(public_key.into()),
            )
        } else {
            false
        }
    };

    if !valid {
        return Err(Error::InvalidDidSignature);
    }

    let w3n = kilt::get_w3n(&payload.iss, &cli).await.unwrap_or("".into());
    let props = serde_json::Map::new();

    // construct id_token and refresh_token

    let mut app_state = app_state.write()?; // may update the rhai checkers
    let id_token = app_state
        .jwt_builder
        .new_id_token(&sender, &w3n, &props, &Some(nonce.clone()))
        .to_jwt(&app_state.jwt_secret_key, &app_state.jwt_algorithm)
        .map_err(|e| {
            log::error!("Failed to create id token: {}", e);
            Error::CreateJWT
        })?;

    let refresh_token = app_state
        .jwt_builder
        .new_refresh_token(&sender, &w3n, &props, &Some(nonce.clone()))
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
