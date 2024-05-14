use crate::{error::Error, AppState};
use actix_web::{post, web, HttpResponse};
use serde::{Deserialize, Serialize};
use std::sync::RwLock;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct TokenResponse {
    pub token_type: String,
    pub refresh_token: String,
    pub id_token: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct TokenRequeryBody {
    pub grant_type: String,
    pub code: String,
    pub redirect_uri: String,
    pub client_id: String,
}

#[post("/api/v1/token")]
async fn post_token_handler(
    app_state: web::Data<RwLock<AppState>>,
    body: web::Json<TokenRequeryBody>,
) -> Result<HttpResponse, Error> {
    if body.grant_type != "authorization_code" {
        return Err(Error::InvalidGrantType);
    }

    let token_storage = {
        let app_state = app_state.read()?;
        app_state.token_storage.clone()
    };

    let (token_response, stored_redirect_uri) = token_storage
        .remove(&body.code)
        .await
        .ok_or(Error::InvalidAuthenticationCode)?;

    if body.redirect_uri != stored_redirect_uri {
        return Err(Error::RedirectUri);
    }

    let app_state = app_state.read()?;

    app_state
        .client_configs
        .get(&body.client_id)
        .ok_or(Error::OauthInvalidClientId)?;

    Ok(HttpResponse::Ok()
        .append_header(("Cache-Control", "no-store"))
        .json(token_response))
}
