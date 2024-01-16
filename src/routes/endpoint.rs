use std::sync::RwLock;

use actix_web::{get, web, HttpResponse};

use crate::{routes::error::Error, AppState};

#[get("/api/v1/endpoint")]
async fn get_endpoint(app_state: web::Data<RwLock<AppState>>) -> Result<HttpResponse, Error> {
    let app_state = app_state.read()?;
    let endpoint_url = app_state.kilt_endpoint.clone();
    Ok(HttpResponse::Ok().json(endpoint_url))
}
