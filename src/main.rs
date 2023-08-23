use actix_session::{
    config::{CookieContentSecurity, PersistentSession},
    storage::CookieSessionStore,
    SessionMiddleware,
};
use actix_web::{
    cookie::{time::Duration, SameSite},
    middleware::Logger,
    web, App, HttpServer,
};
use clap::Parser;
use serde::{Deserialize, Serialize};
use well_known_did_config::create_well_known_did_config;

mod cli;
mod config;
mod jwt;
mod kilt;
mod messages;
mod routes;
mod verify;
mod well_known_did_config;

use crate::{config::CredentialRequirement, jwt::TokenFactory, routes::*};

// shared state
#[derive(Clone, Debug, Serialize, Deserialize)]
struct AppState {
    app_name: String,
    encryption_key_uri: String,
    public_key: Vec<u8>,
    secret_key: Vec<u8>,
    credential_requirements: Vec<CredentialRequirement>,
    token_builder: TokenFactory,
    token_secret: String,
    well_known_did_config: well_known_did_config::WellKnownDidConfig,
    oauth_config: Option<config::OauthConfig>,
}

#[actix_web::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    env_logger::init();

    let cli = cli::Cli::parse();
    cli.set_log_level();

    let config = cli.get_config()?;

    let state = AppState {
        app_name: "simple-auth-relay-app".to_string(),
        encryption_key_uri: config.session_config.key_uri.to_string(),
        public_key: config.get_nacl_public_key()?,
        secret_key: config.get_nacl_secret_key()?,
        credential_requirements: config.credential_requirements.clone(),
        token_builder: config.get_token_factory(),
        token_secret: config.jwt_config.token_secret.clone(),
        well_known_did_config: create_well_known_did_config(&config.well_known_did_config)?,
        oauth_config: config.oauth_config.clone(),
    };

    let host = config.host.clone();
    let port = config.port;

    log::info!("Starting server at {}:{}", host, port);

    HttpServer::new(move || {
        App::new()
            .app_data(web::Data::new(state.clone()))
            .wrap(Logger::default())
            .wrap(
                SessionMiddleware::builder(CookieSessionStore::default(), config.get_session_key())
                    .cookie_content_security(CookieContentSecurity::Private)
                    .cookie_http_only(true)
                    .cookie_same_site(SameSite::Lax)
                    .cookie_secure(config.production)
                    .cookie_name("sara".to_string())
                    .session_lifecycle(
                        PersistentSession::default().session_ttl(Duration::seconds(60)),
                    )
                    .build(),
            )
            .service(challenge_handler)
            .service(challenge_response_handler)
            .service(get_credential_requirements_handler)
            .service(post_credential_handler)
            .service(refresh_handler)
            .service(well_known_did_config_handler)
            .service(authorize_handler)
            .service(actix_files::Files::new("/", &config.base_path).index_file("index.html"))
    })
    .bind((host.as_str(), port))?
    .run()
    .await?;

    Ok(())
}
