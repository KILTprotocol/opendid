use actix_session::{SessionGetError, SessionInsertError};

#[derive(Debug)]
pub enum Error {
    OauthNotConfigured,
    OauthInvalidClientId,
    OauthInvalidRedirectUri,
    OauthNoSession,
    SessionInsert,
    SessionGet,
    InvalidChallenge,
    InvalidNonce,
    InvalidLightDid,
    InvalidPrivateKey,
    CantConnectToBlockchain,
    InvalidFullDid,
    FailedToDecrypt,
    FailedToParseMessage,
    GetChallenge,
    VerifyCredential(String),
    CreateJWT,
    LockPoison,
    Internal(String),
    VerifyJWT,
    InvalidDidSignature,
}

impl std::error::Error for Error {}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        match *self {
            Error::OauthNotConfigured => write!(f, "OAuth is not configured"),
            Error::OauthInvalidClientId => write!(f, "Invalid client_id"),
            Error::OauthInvalidRedirectUri => write!(f, "Invalid redirect_uri"),
            Error::SessionInsert => write!(f, "Failed to insert session"),
            Error::SessionGet => write!(f, "Failed to get session"),
            Error::InvalidChallenge => write!(f, "Invalid challenge"),
            Error::InvalidNonce => write!(f, "Invalid nonce"),
            Error::InvalidLightDid => write!(f, "Invalid light DID"),
            Error::InvalidPrivateKey => write!(f, "Invalid private key"),
            Error::CantConnectToBlockchain => write!(f, "Can't connect to KILT blockchain"),
            Error::InvalidFullDid => write!(f, "Invalid full DID"),
            Error::FailedToDecrypt => write!(f, "Failed to decrypt"),
            Error::FailedToParseMessage => write!(f, "Failed to parse message"),
            Error::GetChallenge => write!(f, "Failed to get challenge"),
            Error::VerifyCredential(ref s) => write!(f, "Failed to verify credential: {}", s),
            Error::CreateJWT => write!(f, "Failed to create JWT"),
            Error::OauthNoSession => write!(f, "No session"),
            Error::LockPoison => write!(f, "Lock poison"),
            Error::Internal(ref s) => write!(f, "Internal error: {}", s),
            Error::VerifyJWT => write!(f, "Failed to verify JWT"),
            Error::InvalidDidSignature => write!(f, "Failed to verify DID Signature"),
        }
    }
}

impl From<Error> for actix_web::Error {
    fn from(e: Error) -> Self {
        match e {
            // bad request
            Error::OauthNotConfigured => {
                actix_web::error::ErrorBadRequest("OAuth is not configured")
            }
            Error::OauthInvalidClientId => actix_web::error::ErrorBadRequest("Invalid client_id"),
            Error::OauthInvalidRedirectUri => {
                actix_web::error::ErrorBadRequest("Invalid redirect_uri")
            }
            Error::InvalidLightDid => actix_web::error::ErrorBadRequest("Invalid light DID"),
            Error::InvalidFullDid => actix_web::error::ErrorBadRequest("Invalid full DID"),
            Error::FailedToDecrypt => actix_web::error::ErrorBadRequest("Failed to decrypt"),
            Error::FailedToParseMessage => {
                actix_web::error::ErrorBadRequest("Failed to parse message")
            }
            Error::GetChallenge => actix_web::error::ErrorBadRequest("Failed to get challenge"),
            Error::VerifyCredential(e) => {
                actix_web::error::ErrorBadRequest(format!("Failed to verify credential: {}", e))
            }
            // unauthorized
            Error::SessionGet => actix_web::error::ErrorUnauthorized("Failed to get session"),
            Error::InvalidChallenge => actix_web::error::ErrorUnauthorized("Invalid challenge"),
            Error::InvalidNonce => actix_web::error::ErrorUnauthorized("Invalid nonce"),
            Error::OauthNoSession => actix_web::error::ErrorUnauthorized("No session"),
            Error::VerifyJWT => actix_web::error::ErrorUnauthorized("Failed to verify JWT"),
            Error::InvalidDidSignature => {
                actix_web::error::ErrorUnauthorized("Failed to verify DID signature")
            }
            // default internal server error
            _ => actix_web::error::ErrorInternalServerError(e),
        }
    }
}

impl From<SessionInsertError> for Error {
    fn from(_: SessionInsertError) -> Self {
        Error::SessionInsert
    }
}

impl From<SessionGetError> for Error {
    fn from(_: SessionGetError) -> Self {
        Error::SessionGet
    }
}

impl<T> From<std::sync::PoisonError<T>> for Error {
    fn from(_: std::sync::PoisonError<T>) -> Self {
        Error::LockPoison
    }
}

impl From<Box<dyn std::error::Error>> for Error {
    fn from(e: Box<dyn std::error::Error>) -> Self {
        Error::Internal(e.to_string())
    }
}
