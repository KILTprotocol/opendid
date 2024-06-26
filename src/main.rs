use std::collections::HashMap;

use actix_cors::Cors;
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
use anyhow::Context;
use clap::Parser;

use moka::future::Cache;
use rhai_checker::RhaiCheckerMap;
use sodiumoxide::crypto::box_;
use tokio::sync::RwLock;
use well_known_did_config::create_well_known_did_config;

mod cli;
mod config;
mod config_updater;
mod constants;
mod jwt;
mod kilt;
mod messages;
mod response_type;
mod rhai_checker;
mod routes;
pub mod serialize;
mod verify;
mod well_known_did_config;

use crate::{constants::SESSION_COOKIE_NAME, jwt::TokenFactory, routes::*};

// Store the token responses and redirect_uri given an authorization code.
pub type TokenStorage = Cache<String, (TokenResponse, TokenMetadata)>;

// shared state
#[derive(Clone, Debug)]
pub struct AppState {
    app_name: String,
    encryption_key_uri: String,
    session_secret_key: box_::SecretKey,
    jwt_builder: TokenFactory,
    jwt_secret_key: String,
    jwt_public_key: Option<String>,
    jwt_algorithm: String,
    well_known_did_config: well_known_did_config::WellKnownDidConfig,
    kilt_endpoint: String,
    client_configs: HashMap<String, config::ClientConfig>,
    rhai_checkers: RhaiCheckerMap,
    token_storage: TokenStorage,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let cli = cli::Cli::parse();
    env_logger::Builder::new()
        .filter_level(cli.verbose.log_level_filter())
        .init();

    let config = cli.get_config()?;

    // let token_storage = Cache
    let state = web::Data::new(RwLock::new(AppState {
        app_name: "OpenDID".to_string(),
        encryption_key_uri: config.session.key_uri.to_string(),
        session_secret_key: config.get_nacl_secret_key()?,
        jwt_builder: config.get_token_factory(),
        jwt_secret_key: config.jwt.secret_key.to_string(),
        jwt_public_key: config.jwt.public_key.clone(),
        jwt_algorithm: config.jwt.algorithm.to_string(),
        well_known_did_config: create_well_known_did_config(&config.well_known_did_config)
            .context("Error creating well-known DID configuration")?,
        kilt_endpoint: config.get_endpoint_url(),
        client_configs: config.clients.clone(),
        rhai_checkers: RhaiCheckerMap::new(),
        token_storage: Cache::builder()
            .time_to_live(std::time::Duration::from_secs(config.session.session_ttl))
            .build(),
    }));

    if let Some(etcd_config) = &config.etcd {
        log::info!("Starting config updater");
        let mut updater =
            config_updater::ConfigUpdater::new(state.clone(), etcd_config.clone()).await?;
        actix_web::rt::spawn(async move {
            if let Err(e) = updater.read_initial_config().await {
                log::error!("Error reading initial config: {}", e);
                std::process::exit(1);
            }
            if let Err(e) = updater.watch_for_updates().await {
                log::error!("Error updating config: {}", e);
                std::process::exit(1);
            }
        });
    }

    let host = config.host.clone();
    let port = config.port;

    log::info!("Starting server at {}:{}", host, port);

    HttpServer::new(move || {
        let cors = Cors::permissive();

        App::new()
            .app_data(web::Data::clone(&state))
            .wrap(Logger::default())
            .wrap(cors)
            .wrap(
                SessionMiddleware::builder(CookieSessionStore::default(), config.get_session_key())
                    .cookie_content_security(CookieContentSecurity::Private)
                    .cookie_http_only(true)
                    .cookie_same_site(SameSite::Lax)
                    .cookie_secure(config.production)
                    .cookie_name(SESSION_COOKIE_NAME.to_string())
                    .session_lifecycle(
                        PersistentSession::default().session_ttl(Duration::seconds(
                            i64::try_from(config.get_session_ttl())
                                .expect("session ttl value is too large"),
                        )),
                    )
                    .build(),
            )
            .service(challenge_handler)
            .service(challenge_response_handler)
            .service(get_credential_requirements_handler)
            .service(post_credential_handler)
            .service(refresh_handler)
            .service(well_known_did_config_handler)
            .service(login_with_did)
            .service(authorize_handler)
            .service(health)
            .service(get_endpoint)
            .service(post_token_handler)
            .service(actix_files::Files::new("/", &config.base_path).index_file("index.html"))
    })
    .bind((host.as_str(), port))?
    .run()
    .await?;

    Ok(())
}
