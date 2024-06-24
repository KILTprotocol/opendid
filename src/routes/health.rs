use crate::{error::Error, kilt::{self, get_did_doc}, AppState};
use actix_web::{get, web, HttpResponse};
use tokio::sync::RwLock;

#[get("/api/v1/health")]
async fn health(app_state: web::Data<RwLock<AppState>>) -> Result<HttpResponse, Error> {
    let issuer_did = {
        let app_state = app_state.read().await;
        app_state.jwt_builder.issuer.clone()
    };
    let endpoint = {
        let app_state = app_state.read().await;
        app_state.kilt_endpoint.clone()
    };
    let cli = kilt::connect(&endpoint)
        .await
        .map_err(|_| Error::CantConnectToBlockchain)?;
     get_did_doc(&issuer_did, &cli).await?;
    Ok(HttpResponse::Ok().finish())
}
