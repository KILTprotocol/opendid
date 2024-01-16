use std::sync::RwLock;

use actix_web::{get, web, HttpResponse};

use crate::{routes::error::Error, utils::get_endpoint_url, AppState};

#[get("/api/v1/endpoint")]
async fn get_endpoint(app_state: web::Data<RwLock<AppState>>) -> Result<HttpResponse, Error> {
    let app_state = app_state.read()?;
    let endpoint_url = get_endpoint_url(&app_state.kilt_endpoint);
    Ok(HttpResponse::Ok().json(endpoint_url))
}
