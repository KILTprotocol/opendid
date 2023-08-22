use actix_session::{SessionInsertError, SessionGetError};


#[derive(Debug)]
pub enum Error {
    OauthNotConfigured,
    OauthInvalidClientId,
    OauthInvalidRedirectUri,
    SessionInsertError(SessionInsertError),
    SessionGetError,
    InvalidChallenge,
    InvalidNonce,
    InvalidLightDid,
    InvalidPrivateKey,
    Other(String),
}

impl std::error::Error for Error {}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        match *self {
            Error::OauthNotConfigured => write!(f, "OAuth is not configured"),
            Error::OauthInvalidClientId => write!(f, "Invalid client_id"),
            Error::OauthInvalidRedirectUri => write!(f, "Invalid redirect_uri"),
            Error::SessionInsertError(ref e) => write!(f, "SessionInsertError: {}", e),
            Error::SessionGetError => write!(f, "Failed to get session"),
            Error::InvalidChallenge => write!(f, "Invalid challenge"),
            Error::InvalidNonce => write!(f, "Invalid nonce"),
            Error::InvalidLightDid => write!(f, "Invalid light DID"),
            Error::InvalidPrivateKey => write!(f, "Invalid private key"),
            Error::Other(ref s) => write!(f, "{}", s),
        }
    }
}

impl Into<actix_web::Error> for Error {
    fn into(self) -> actix_web::Error {
        match self {
            // bad request
            Error::OauthNotConfigured => actix_web::error::ErrorBadRequest("OAuth is not configured"),
            Error::OauthInvalidClientId => actix_web::error::ErrorBadRequest("Invalid client_id"),
            Error::OauthInvalidRedirectUri => actix_web::error::ErrorBadRequest("Invalid redirect_uri"),
            Error::InvalidLightDid => actix_web::error::ErrorBadRequest("Invalid light DID"),
            // unauthorized
            Error::SessionGetError => actix_web::error::ErrorUnauthorized("Failed to get session"),
            Error::InvalidChallenge => actix_web::error::ErrorUnauthorized("Invalid challenge"),
            Error::InvalidNonce => actix_web::error::ErrorUnauthorized("Invalid nonce"),
            // default internal server error
            _ => actix_web::error::ErrorInternalServerError(self),
        }
    }
}

impl From<SessionInsertError> for Error {
    fn from(e: SessionInsertError) -> Self {
        Error::SessionInsertError(e)
    }
}

impl From<SessionGetError> for Error {
    fn from(_: SessionGetError) -> Self {
        Error::SessionGetError
    }
}

