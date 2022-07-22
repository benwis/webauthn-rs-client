use thiserror::Error;
use wasm_bindgen::JsValue;

#[derive(Error, Debug)]
pub enum WebauthnClientError {
    #[error("unknown webauthn error")]
    Unknown,
    #[error("Corrupt Session")]
    CorruptSession,
    #[error("Future Error")]
    FutureError,
    #[error("User Not Found")]
    UserNotFound,
    #[error("User Has No Credentials")]
    UserHasNoCredentials,
    #[error("Invalid UUID")]
    UUIDError,
    #[error("Header Error")]
    HeaderError,
    #[error("Challenge Response Error")]
    ChallengeResponseError,
    #[error("Challenge Request Error")]
    ChallengeRequestError,
    #[error("Key Response Error")]
    KeyResponseError,
    #[error("Key Request Error")]
    KeyRequestError,
    #[error("Response Parse Error")]
    ResponseParseError,
    #[error("Webauthn Server Error: `{0}`")]
    WebauthnServerError(String),
    #[error("Webauthn Client Error: `{0}`")]
    WebauthnClientError(String),
    #[error("RegisterPublicKeyCredential Error: `{0}`")]
    RegisterPublicKeyCredentialError(String),
    #[error("CreatePublicKeyCredential Error: `{0}`")]
    CreatePublicKeyCredentialError(String),
    #[error("RegisterPublicKey Error: {0}")]
    RegisterPublicKeyError(String),
    #[error("Webauthn Server Login Error: `{0}`")]
    WebauthnServerLoginError(String),
    #[error("JsError: `{0}`")]
    WebauthnJsError(String),
    #[error("Unable to get Global Window")]
    WindowError,
    #[error("Authorization Error: `{0}`")]
    AuthorizationError(String),
}
impl From<WebauthnClientError> for JsValue {
    fn from(wce: WebauthnClientError) -> Self {
        JsValue::from(wce.to_string())
    }
}
