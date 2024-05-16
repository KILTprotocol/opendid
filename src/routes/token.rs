use crate::{error::Error, AppState};
use actix_web::{post, web, HttpResponse};
use serde::{Deserialize, Serialize};
use tokio::sync::RwLock;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct TokenResponse {
    pub token_type: String,
    pub refresh_token: String,
    pub id_token: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct TokenRequestBody {
    pub grant_type: String,
    pub code: String,
    // pub redirect_uri: String,
}

#[post("/api/v1/token")]
async fn post_token_handler(
    app_state: web::Data<RwLock<AppState>>,
    body: web::Json<TokenRequestBody>,
) -> Result<HttpResponse, Error> {
    log::info!("POST token");


    if body.grant_type != "authorization_code" {
    log::info!("invaild grant_type");
        return Err(Error::InvalidGrantType);
    }

    let token_storage = {
        let app_state = app_state.read().await;
        app_state.token_storage.clone()
    };

    let (token_response, stored_redirect_uri) = token_storage
        .remove(&body.code)
        .await
        .ok_or(Error::InvalidAuthenticationCode)?;

    // if body.redirect_uri != stored_redirect_uri {
    //     return Err(Error::RedirectUri);
    // }

    Ok(HttpResponse::Ok()
        .append_header(("Cache-Control", "no-store"))
        .json(token_response))
}
