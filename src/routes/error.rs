use actix_session::{SessionGetError, SessionInsertError};

#[derive(Debug)]
pub enum Error {
    OauthNotConfigured,
    OauthInvalidClientId,
    OauthInvalidRedirectUri,
    OauthNoSession,
    SessionInsert,
    SessionGet,
    InvalidChallenge(&'static str),
    InvalidNonce,
    InvalidLightDid(&'static str),
    CantConnectToBlockchain,
    InvalidDid(&'static str),
    FailedToDecrypt,
    FailedToParseMessage,
    GetChallenge,
    VerifyCredential(String),
    CreateJWT,
    Internal(String),
    VerifyJWT(String),
    InvalidDidSignature,
    ResponseType,
    RedirectUri,
    InvalidAuthenticationCode,
    UnsupportedFlow,
    InvalidGrantType,
}

impl std::error::Error for Error {}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        match self {
            Error::OauthNotConfigured => write!(f, "OAuth is not configured"),
            Error::OauthInvalidClientId => write!(f, "Invalid client_id"),
            Error::OauthInvalidRedirectUri => write!(f, "Invalid redirect_uri"),
            Error::SessionInsert => write!(f, "Failed to insert session"),
            Error::SessionGet => write!(f, "Failed to get session"),
            Error::InvalidChallenge(s) => write!(f, "Invalid challenge: {}", s),
            Error::InvalidNonce => write!(f, "Invalid nonce"),
            Error::InvalidLightDid(s) => write!(f, "Invalid light DID: {}", s),
            Error::CantConnectToBlockchain => write!(f, "Can't connect to KILT blockchain"),
            Error::InvalidDid(s) => write!(f, "Invalid DID: {}", s),
            Error::FailedToDecrypt => write!(f, "Failed to decrypt"),
            Error::FailedToParseMessage => write!(f, "Failed to parse message"),
            Error::GetChallenge => write!(f, "Failed to get challenge"),
            Error::VerifyCredential(s) => write!(f, "Failed to verify credential: {}", s),
            Error::CreateJWT => write!(f, "Failed to create JWT"),
            Error::OauthNoSession => write!(f, "No session"),
            Error::VerifyJWT(s) => write!(f, "Failed to verify JWT {} ", s),
            Error::InvalidDidSignature => write!(f, "Failed to verify DID Signature"),
            Error::Internal(s) => write!(f, "Internal error: {}", s),
            Error::ResponseType => write!(f, "Invalid response-type"),
            Error::RedirectUri => write!(f, "Missing or mismatched redirect_uri"),
            Error::InvalidAuthenticationCode => {
                write!(f, "Authorization Code is invalid or expired")
            }
            Error::UnsupportedFlow => write!(f, "Unsupported authorization processing flow"),
            Error::InvalidGrantType => write!(f, "Invalid grant-type value"),
        }
    }
}

impl From<Error> for actix_web::Error {
    fn from(e: Error) -> Self {
        match e {
            // bad request
            Error::OauthNotConfigured
            | Error::OauthInvalidClientId
            | Error::OauthInvalidRedirectUri
            | Error::InvalidLightDid(_)
            | Error::InvalidDid(_)
            | Error::FailedToDecrypt
            | Error::FailedToParseMessage
            | Error::InvalidAuthenticationCode
            | Error::VerifyCredential(_)
            | Error::RedirectUri
            | Error::UnsupportedFlow
            | Error::InvalidGrantType
            | Error::ResponseType
            | Error::GetChallenge => actix_web::error::ErrorBadRequest(e),
            // unauthorized
            Error::SessionGet
            | Error::InvalidChallenge(_)
            | Error::InvalidNonce
            | Error::VerifyJWT(_)
            | Error::InvalidDidSignature
            | Error::OauthNoSession => actix_web::error::ErrorUnauthorized(e),
            // Internal errors. we don't pass the error message to the frontend to not leak information.
            Error::SessionInsert
            | Error::CantConnectToBlockchain
            | Error::CreateJWT
            | Error::Internal(_)
            | Error::LockPoison => {
                log::error!("Internal Error: {}", e);
                actix_web::error::ErrorInternalServerError("Internal Error")
            }
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

impl From<Box<dyn std::error::Error>> for Error {
    fn from(e: Box<dyn std::error::Error>) -> Self {
        Error::Internal(e.to_string())
    }
}

impl From<subxt::Error> for Error {
    fn from(e: subxt::Error) -> Self {
        Error::Internal(e.to_string())
    }
}
