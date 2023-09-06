use std::sync::RwLock;

use actix_session::Session;
use actix_web::{get, web, HttpResponse};
use serde::{Deserialize, Serialize};

use crate::{constants::OIDC_SESSION_KEY, routes::error::Error, AppState};

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AuthorizeQueryParameters {
    pub client_id: String,
    pub redirect_uri: String,
    pub response_type: String,
    pub scope: String,
    pub state: String,
    pub nonce: String,
}

/// This handler is the oauth entrypoint. It parses the query parameters and checks if the client_id and redirect_uri are valid.
/// after that it stores the query parameters in the session and redirects the user to the login page.
#[get("/api/v1/authorize")]
async fn authorize_handler(
    session: Session,
    app_state: web::Data<RwLock<AppState>>,
    query: web::Query<AuthorizeQueryParameters>,
) -> Result<HttpResponse, Error> {
    log::info!("GET authorize handler");
    let app_state = app_state.read()?;
    let redirect_urls = &app_state
        .client_configs
        .get(&query.client_id)
        .ok_or(Error::OauthInvalidClientId)?
        .redirect_urls;

    if redirect_urls.contains(&query.redirect_uri) {
        session.insert(OIDC_SESSION_KEY, query.clone().into_inner())?;
        return Ok(HttpResponse::Found()
            .append_header(("Location", "/"))
            .finish());
    } else {
        Err(Error::OauthInvalidRedirectUri)
    }
}
