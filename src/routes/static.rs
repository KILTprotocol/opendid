use actix_web::{post, web, HttpResponse, Responder};
use serde::Deserialize;
use serde_json::json;

use crate::AppState;

// a actix-web handler function to serve a static frontend from a base directory
