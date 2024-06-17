use std::str::FromStr;

use actix_session::Session;
use actix_web::{get, web, HttpResponse};
use serde::{Deserialize, Serialize};
use tokio::sync::RwLock;
use url::Url;

use crate::{
    constants::OIDC_SESSION_KEY, response_type::ResponseType, routes::error::Error, AppState,
};

/// Unvalidated query parameters for `/authorize`.
///
/// Some required parameters are optional in this struct to allow validation
/// and returning proper errors instead serialization errors.
///
/// Convert to [`ValidatedAuthorizeParameters`] after validating the parameters.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AuthorizeQueryParameters {
    pub client_id: Option<String>,
    pub redirect_uri: String,
    pub response_type: Option<String>,
    pub scope: Option<String>,
    pub state: Option<String>,
    pub nonce: Option<String>,
}

/// The valid parameters needed for for `/authorize`.
///
/// Can be created from the values of [`AuthorizeQueryParameters`] after validation.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ValidatedAuthorizeParameters {
    pub client_id: String,
    pub redirect_uri: Url,
    pub response_type: ResponseType,
    pub scope: String,
    pub state: Option<String>,
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

    // Return an error without redirecting, if the `redirect_uri` is an invalid URL.
    let redirect_uri =
        Url::parse(&query.redirect_uri).map_err(|_| Error::OauthInvalidRedirectUri)?;

    // `client_id` must be present.
    let client_id: String = if let Some(client_id) = &query.client_id {
        client_id.clone()
    } else {
        return error_redirect(
            redirect_uri,
            Error::OauthInvalidClientId,
            query.state.as_deref(),
        );
    };

    // `response_type` is required.
    let response_type: &str = if let Some(response_type) = &query.response_type {
        response_type
    } else {
        return error_redirect(redirect_uri, Error::ResponseType, query.state.as_deref());
    };

    let client_configs = if let Some(configs) = app_state.client_configs.get(&client_id) {
        configs
    } else {
        return error_redirect(
            Url::parse(&query.redirect_uri).unwrap(),
            Error::OauthInvalidClientId,
            query.state.as_deref(),
        );
    };

    let redirect_urls: &Vec<url::Url> = &client_configs.redirect_urls;
    let requirements_empty = client_configs.requirements.is_empty();

    // Support Authorization Code Flow and Implicit Flow.
    let response_type = ResponseType::from_str(response_type)?;

    // Implicit flow must include a nonce.
    if response_type.is_implicit_flow() && query.nonce.is_none() {
        return error_redirect(redirect_uri, Error::InvalidNonce, query.state.as_deref());
    }

    let is_redirect_uri_in_query = redirect_urls.contains(&redirect_uri);
    if !is_redirect_uri_in_query {
        return error_redirect(
            redirect_uri,
            Error::OauthInvalidRedirectUri,
            query.state.as_deref(),
        );
    }

    let validated_authorize_parameters = ValidatedAuthorizeParameters {
        client_id,
        redirect_uri,
        response_type,
        scope: query.scope.clone().unwrap_or_default(),
        state: query.state.clone(),
        nonce: query.nonce.clone(),
    };

    match (requirements_empty, &query.nonce) {
        (true, Some(nonce)) => {
            // SIOPV2
            session.insert(OIDC_SESSION_KEY, validated_authorize_parameters)?;
            let redirect_uri_with_nonce = format!("/?nonce={}", nonce);
            Ok(HttpResponse::Found()
                .append_header(("Location", redirect_uri_with_nonce))
                .finish())
        }
        _ => {
            session.insert(OIDC_SESSION_KEY, validated_authorize_parameters)?;
            Ok(HttpResponse::Found()
                .append_header(("Location", "/"))
                .finish())
        }
    }
}

/// Creates a 302 response with an error.
fn error_redirect(
    mut redirect_uri: Url,
    error: Error,
    state: Option<&str>,
) -> Result<HttpResponse, Error> {
    redirect_uri
        .query_pairs_mut()
        .append_pair("error", "invalid_request")
        .append_pair("error_description", &error.to_string());
    if let Some(state) = state {
        redirect_uri.query_pairs_mut().append_pair("state", state);
    };
    Ok(HttpResponse::Found()
        .append_header(("Location", redirect_uri.to_string()))
        .finish())
}
