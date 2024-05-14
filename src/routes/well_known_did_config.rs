
use actix_web::{get, web, HttpResponse};
use tokio::sync::RwLock;

use crate::{routes::error::Error, AppState};

#[get("/.well-known/did-configuration.json")]
async fn well_known_did_config_handler(
    app_state: web::Data<RwLock<AppState>>,
) -> Result<HttpResponse, Error> {
    let app_state = app_state.read().await;
    Ok(HttpResponse::Ok().json(&app_state.well_known_did_config))
}
