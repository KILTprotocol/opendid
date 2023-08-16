use actix_web::{get, web, Responder};

use crate::AppState;


#[get("/.well-known/did-configuration.json")]
async fn well_known_did_config_handler(
    app_state: web::Data<AppState>,
) -> impl Responder {
    // return app_state.well_known_did_config as JSON
    web::Json(app_state.well_known_did_config.clone())
}