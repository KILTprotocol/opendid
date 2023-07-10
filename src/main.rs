
use actix_web::{web, App, HttpResponse, HttpServer, Responder, cookie::{SameSite, time::Duration}, middleware::Logger};
use actix_session::{Session, SessionMiddleware, storage::CookieSessionStore, config::{CookieContentSecurity, PersistentSession}};

use kilt::{runtime_types::{did::did_details::DidVerificationKey, attestation::attestations::AttestationDetails}, KiltConfig};
use serde::{Serialize, Deserialize};
use base58::{FromBase58};

use serde_json::json;
use serde_with::{serde_as, Bytes};
use sodiumoxide::crypto::{box_};

mod kilt;
mod config;
use config::{Config, CredentialRequirement};

mod messages;
use messages::{EncryptedMessage, MessageBody, Message};
use sp_core::{H256, Decode, crypto::Ss58Codec};
use sp_runtime::codec::IoReader;
use sp_runtime::traits::Verify;
use subxt::{utils::{AccountId32}, OnlineClient};

use crate::kilt::runtime_types::did::did_details::{DidPublicKey, DidEncryptionKey};

mod util;

mod jwt;

use crate::jwt::{TokenBuilder};

mod routes;

use routes::*;

// shared state
#[derive(Clone, Debug, Serialize, Deserialize)]
struct AppState {
    app_name: String,
    encryption_key_uri: String,
    public_key: Vec<u8>,
    secret_key: Vec<u8>,
    credential_requirements: Vec<CredentialRequirement>,
    token_builder: TokenBuilder,
}


#[actix_web::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {

    std::env::set_var("RUST_LOG", "info");
    env_logger::init();

    let matches = clap::Command::new("kiltlogin")
            .arg(clap::Arg::new("session-key")
            .long("session-key")
            .value_name("SESSION_KEY")
            .help("Sets the cookie session key")
        )
        .arg(clap::Arg::new("nacl-public-key")
            .long("nacl-public-key")
            .value_name("NACL_PUBLIC_KEY")
            .help("Sets the nacl public key")
        )
        .arg(clap::Arg::new("nacl-secret-key")
            .long("nacl-secret-key")
            .value_name("NACL_SECRET_KEY")
            .help("Sets the nacl secret key")
        )
        .arg(clap::Arg::new("key-uri")
            .short('k')
            .long("key-uri")
            .value_name("KEY_URI")
            .help("Sets the encryption key uri")
        )
        .arg(clap::Arg::new("config")
            .short('c')
            .long("config")
            .value_name("CONFIG")
            .help("Sets the config path")
        )
        .get_matches();

    
    let config_path = matches.get_one::<String>("config");
    let mut config = match config_path {
        Some(config_path) => {
            let config_file = std::fs::File::open(config_path)?;
            let config: Config = serde_yaml::from_reader(config_file)?;
            config
        },
        None => {
            Config {
                host: "127.0.0.1".to_string(),
                port: 3002,
                session_key: matches.get_one::<String>("session-key").ok_or("missing session key")?.clone(),
                key_uri: matches.get_one::<String>("key-uri").ok_or("missing key uri")?.clone(),
                nacl_public_key: matches.get_one::<String>("nacl-public-key").ok_or("missing nacl public key")?.clone(),
                nacl_secret_key: matches.get_one::<String>("nacl-secret-key").ok_or("missing nacl secret key")?.clone(),
                credential_requirements: vec![],
                token_issuer: "dev-auth".to_string(),
                access_token_lifetime: 60,
                refresh_token_lifetime: 60 * 60 * 24 * 30,
                access_token_audience: "application".to_string(),
                refresh_token_audience: "authentication".to_string(),
            }
        }
    };

    if let Some(pk) = matches.get_one::<String>("nacl-public-key") {
        config.nacl_public_key = pk.clone();
    }
    if let Some(sk) = matches.get_one::<String>("nacl-secret-key") {
        config.nacl_secret_key = sk.clone();
    }
    if let Some(key_uri) = matches.get_one::<String>("key-uri") {
        config.key_uri = key_uri.clone();
    }

    let state = AppState {
        app_name: "kiltlogin".to_string(),
        encryption_key_uri: config.key_uri.to_string(),
        public_key: config.get_nacl_public_key()?,
        secret_key: config.get_nacl_secret_key()?,
        credential_requirements: config.credential_requirements.clone(),
        token_builder: config.get_token_builder(),
    };

    let host = config.host.clone();
    let port = config.port.clone();

    HttpServer::new(move || {
        App::new()
            .app_data(web::Data::new(state.clone()))
            .wrap(Logger::default())
            .wrap(
                SessionMiddleware::builder(
                    CookieSessionStore::default(),
                    config.get_session_key(),
                )
                .cookie_content_security(CookieContentSecurity::Private)
                .cookie_http_only(true)
                .cookie_same_site(SameSite::Lax)
                .cookie_secure(false) // TODO: set to true when using HTTPS!
                .cookie_name("kiltlogin".to_string())
                .session_lifecycle(
                    PersistentSession::default().session_ttl(Duration::seconds(60))
                )
                .build()
            )
            .service(challenge_handler)
            .service(challenge_response_handler)
            .service(get_credential_requirements_handler)
            .service(post_credential_handler)
    })
    .bind((host.as_str(), port))?
    .run()
    .await?;

    Ok(())
}
