use std::str::FromStr;
use serde::{Deserialize, Serialize};
use crate::error::Error;

// Authorization Code Flow and Implicit Flow are supported.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ResponseType {
    IdToken,
    IdTokenToken,
    Code,
}

impl FromStr for ResponseType {
    type Err = Error;

    fn from_str(input: &str) -> Result<Self, Self::Err> {
        match input {
            "id_token" => Ok(ResponseType::IdToken),
            "id_token token" => Ok(ResponseType::IdTokenToken),
            "code" => Ok(ResponseType::Code),
            _ => Err(Error::UnsupportedFlow),
        }
    }
}

impl ResponseType {
    pub fn is_authorization_code_flow(&self) -> bool {
        matches!(self, ResponseType::Code)
    }
    pub fn is_implicit_flow(&self) -> bool {
        matches!(self, ResponseType::IdToken | ResponseType::IdTokenToken)
    }
}
