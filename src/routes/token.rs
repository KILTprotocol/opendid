use crate::{error::Error, AppState};
use actix_web::{post, web, HttpResponse};
use serde::{Deserialize, Serialize};
use tokio::sync::RwLock;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct TokenResponse {
    pub access_token: String,
    pub token_type: String,
    pub refresh_token: String,
    pub id_token: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct TokenMetadata {
    pub client_id: String,
    pub redirect_uri: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct TokenRequestBody {
    pub grant_type: String,
    pub code: String,
    pub redirect_uri: String,
    pub client_secret: Option<String>,
}

#[post("/api/v1/token")]
async fn post_token_handler(
    app_state: web::Data<RwLock<AppState>>,
    body: web::Form<TokenRequestBody>,
) -> Result<HttpResponse, Error> {
    log::info!("POST token");

    if body.grant_type != "authorization_code" {
        return Err(Error::InvalidGrantType);
    }

    let token_storage = {
        let app_state = app_state.read().await;
        app_state.token_storage.clone()
    };

    let (token_response, response_metadata) = token_storage
        .get(&body.code)
        .await
        .ok_or(Error::InvalidAuthorizationCode)?;

    let client_secret: Option<String> = {
        let app_state = app_state.read().await;
        app_state
            .client_configs
            .get(&response_metadata.client_id)
            .ok_or(Error::OauthInvalidClientId)?
            .client_secret
            .clone()
    };

    if client_secret != body.client_secret {
        return Err(Error::InvalidClientSecret);
    }

    if body.redirect_uri != response_metadata.redirect_uri {
        return Err(Error::RedirectUri);
    }

    token_storage.invalidate(&body.code).await;

    Ok(HttpResponse::Ok()
        .append_header(("Cache-Control", "no-store"))
        .json(token_response))
}
