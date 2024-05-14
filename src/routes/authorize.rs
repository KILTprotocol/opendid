
use actix_session::Session;
use actix_web::{get, web, HttpResponse};
use serde::{Deserialize, Serialize};
use tokio::sync::RwLock;

use crate::{
    constants::{OIDC_SESSION_KEY, REDIRECT_URI_SESSION_KEY, RESPONSE_TYPE_SESSION_KEY},
    routes::error::Error,
    AppState,
};

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AuthorizeQueryParameters {
    pub client_id: String,
    pub redirect_uri: String,
    pub response_type: String,
    pub scope: String,
    pub state: String,
    pub nonce: Option<String>,
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
    let app_state = app_state.read().await;
    let redirect_urls = &app_state
        .client_configs
        .get(&query.client_id)
        .ok_or(Error::OauthInvalidClientId)?
        .redirect_urls;

    let are_requirements_empty = &app_state
        .client_configs
        .get(&query.client_id)
        .ok_or(Error::OauthInvalidClientId)?
        .requirements
        .is_empty();

    let is_redirect_uri_in_query = redirect_urls.contains(&query.redirect_uri);

    session.insert(REDIRECT_URI_SESSION_KEY, query.redirect_uri.clone())?;
    session.insert(RESPONSE_TYPE_SESSION_KEY, query.response_type.clone())?;

    if query.response_type == "id_token" && query.nonce.is_none() {
        return Err(Error::InvalidNonce);
    }

    match (
        are_requirements_empty,
        is_redirect_uri_in_query,
        &query.nonce,
    ) {
        (true, true, Some(nonce)) => {
            session.insert(OIDC_SESSION_KEY, query.clone().into_inner())?;
            let redirect_uri_with_nonce = format!("/?nonce={}", nonce);
            Ok(HttpResponse::Found()
                .append_header(("Location", redirect_uri_with_nonce))
                .finish())
        }
        (false, true, _) | (true, true, None) => {
            session.insert(OIDC_SESSION_KEY, query.clone().into_inner())?;
            Ok(HttpResponse::Found()
                .append_header(("Location", "/"))
                .finish())
        }
        _ => Err(Error::OauthInvalidRedirectUri),
    }
}
