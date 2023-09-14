use std::{collections::HashMap, sync::RwLock};

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

use rhai_checker::RhaiCheckerMap;
use well_known_did_config::create_well_known_did_config;

mod cli;
mod config;
mod config_updater;
mod constants;
mod jwt;
mod kilt;
mod messages;
mod rhai_checker;
mod routes;
mod verify;
mod well_known_did_config;

use crate::{constants::SESSION_COOKIE_NAME, jwt::TokenFactory, routes::*};

// shared state
#[derive(Clone, Debug)]
pub struct AppState {
    app_name: String,
    encryption_key_uri: String,
    session_secret_key: Vec<u8>,
    jwt_builder: TokenFactory,
    jwt_secret_key: String,
    jwt_public_key: Option<String>,
    jwt_algorithm: String,
    well_known_did_config: well_known_did_config::WellKnownDidConfig,
    kilt_endpoint: String,
    client_configs: HashMap<String, config::ClientConfig>,
    rhai_checkers: RhaiCheckerMap,
}

#[actix_web::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let cli = cli::Cli::parse();
    env_logger::Builder::new()
        .filter_level(cli.verbose.log_level_filter())
        .init();

    let config = cli.get_config()?;

    let state = web::Data::new(RwLock::new(AppState {
        app_name: "OpenDID".to_string(),
        encryption_key_uri: config.session.key_uri.to_string(),
        session_secret_key: config.get_nacl_secret_key()?,
        jwt_builder: config.get_token_factory(),
        jwt_secret_key: config.jwt.secret_key.to_string(),
        jwt_public_key: config.jwt.public_key.clone(),
        jwt_algorithm: config.jwt.algorithm.to_string(),
        well_known_did_config: create_well_known_did_config(&config.well_known_did_config)?,
        kilt_endpoint: config
            .kilt_endpoint
            .clone()
            .unwrap_or("spiritnet".to_string()),
        client_configs: config.clients.clone(),
        rhai_checkers: RhaiCheckerMap::new(),
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
        App::new()
            .app_data(state.clone())
            .wrap(Logger::default())
            .wrap(
                SessionMiddleware::builder(CookieSessionStore::default(), config.get_session_key())
                    .cookie_content_security(CookieContentSecurity::Private)
                    .cookie_http_only(true)
                    .cookie_same_site(SameSite::Lax)
                    .cookie_secure(config.production)
                    .cookie_name(SESSION_COOKIE_NAME.to_string())
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
