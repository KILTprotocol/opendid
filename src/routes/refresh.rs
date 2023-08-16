use actix_web::{post, web, HttpResponse, Responder};
use serde::Deserialize;
use serde_json::json;

use crate::AppState;

#[derive(Deserialize)]
struct RefreshTokenContainer {
    #[serde(rename = "refreshToken")]
    refresh_token: String,
}

#[post("/api/v1/refresh")]
async fn refresh_handler(
    app_state: web::Data<AppState>,
    refresh_token: web::Json<RefreshTokenContainer>,
) -> impl Responder {
    let jwt = refresh_token.refresh_token.clone();
    let token = match app_state
        .token_builder
        .parse_refresh_token(&jwt, &app_state.token_secret)
    {
        Ok(token) => token,
        Err(_) => return HttpResponse::Unauthorized().body("Invalid token"),
    };
    let access_token = match app_state
        .token_builder
        .new_access_token(&token.subject, &token.properties)
        .to_jwt(&app_state.token_secret)
    {
        Ok(token) => token,
        Err(_) => return HttpResponse::Unauthorized().body("Invalid token"),
    };
    let refresh_token = match app_state
        .token_builder
        .new_refresh_token(&token.subject, &token.properties)
        .to_jwt(&app_state.token_secret)
    {
        Ok(token) => token,
        Err(_) => return HttpResponse::Unauthorized().body("Invalid token"),
    };
    HttpResponse::Ok().json(json!({
        "accessToken": access_token,
        "refreshToken": refresh_token,
    }))
}
