use actix_session::Session;
use actix_web::{get, web, HttpResponse, Responder};
use serde::{Serialize, Deserialize};

use crate::AppState;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AuthorizeQueryParameters {
    pub client_id: String,
    pub redirect_uri: String,
    pub response_type: String,
    pub scope: String,
    pub state: String,
    pub nonce: String,
}

// This handler is the oauth entrypoint. It parses the query parameters and checks of the client_id and redirect_uri are valid.
// after that it stores the query parameters in the session and redirects the user to the login page.

#[get("/api/v1/authorize")]
async fn authorize_handler(session: Session, app_state: web::Data<AppState>, query: web::Query<AuthorizeQueryParameters>) -> impl Responder {
    log::info!("GET authorize handler");
    if let Some(oauth_config) =&app_state.oauth_config {
        let redirect_urls = oauth_config.redirect_urls.get(&query.client_id);
        if let Some(redirect_urls) = redirect_urls {
            if redirect_urls.contains(&query.redirect_uri) {
                session.insert("oauth-context", query.clone().into_inner()).unwrap();
                return HttpResponse::Found().append_header(("Location", "/")).finish();
            } else {
                return HttpResponse::BadRequest().body("Invalid redirect_uri");
            }
        } else {
            return HttpResponse::BadRequest().body("Invalid client_id");
        }
    }
    return HttpResponse::BadRequest().body("OAuth is not configured");
}