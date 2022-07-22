use wasm_bindgen::prelude::*;
use webauthn_rs_proto::*;
mod error;
use error::WebauthnClientError;
use gloo::console;
use serde::{Deserialize, Serialize};
use wasm_bindgen::JsCast;
use wasm_bindgen_futures::JsFuture;
use web_sys::{Headers, Request, RequestCredentials, RequestInit, RequestMode, Response};
// These functions refer to the registration process
#[wasm_bindgen]
/// This is the WASM accessible function that handles the authentication process
pub async fn process_registration(
    tenant_name: String,
    user_name: String,
    start_register_url: String,
    finish_register_url: String,
) -> Result<(), JsError> {
    // Get CreationChallengeResponse from the server
    let ccr =
        get_creation_challenge_response(&tenant_name, &user_name, &start_register_url).await?;
    // Trigger the browser to sign it
    let rpkc = create_register_public_key_credential(ccr).await?;
    // Send it to the server for final verification and storage
    send_register_public_key_credential(rpkc, &finish_register_url).await?;
    Ok(())
}

pub async fn get_creation_challenge_response(
    tenant_name: &str,
    user_name: &str,
    start_register_url: &str,
) -> Result<CreationChallengeResponse, WebauthnClientError> {
    // console::log!("Getting Challenge!");

    let headers = Headers::new().map_err(|_| WebauthnClientError::HeaderError)?;
    headers
        .append("Content-Type", "application/json")
        .map_err(|_| WebauthnClientError::HeaderError)?;

    let mut opts = RequestInit::new();
    opts.method("POST");
    opts.mode(RequestMode::Cors);
    opts.headers(&headers);
    opts.credentials(RequestCredentials::Include);

    //default is format!("/register_start/{}", user_name)
    let dest = format!("{}/{}/{}", start_register_url, tenant_name, user_name);
    let request = Request::new_with_str_and_init(&dest, &opts)
        .map_err(|_| WebauthnClientError::ChallengeRequestError)?;

    let window = web_sys::window().ok_or(WebauthnClientError::WindowError)?;

    let resp_value = JsFuture::from(window.fetch_with_request(&request))
        .await
        .map_err(|_| WebauthnClientError::FutureError)?;
    let resp: Response = resp_value.dyn_into().unwrap_throw();
    let status = resp.status();

    if status == 200 {
        let jsval = JsFuture::from(resp.json().expect("Unable to convert response to JSON!"))
            .await
            .expect("Unable to create Future!");

        let ccr: CreationChallengeResponse = jsval.into_serde().map_err(|_| {
            WebauthnClientError::WebauthnClientError(
                "Failed to convert to CreationChallengeResponse".to_string(),
            )
        })?;
        console::log!(format!("ccr -> {:?}", ccr).as_str());

        // console::log!(format!("Sending Payload -> {:?}", ccr).as_str());
        Ok(ccr)
    } else {
        Err(WebauthnClientError::WebauthnServerError(
            "Unable to get 200 from challenge!".to_string(),
        ))
    }
}

/// Now that we have a CreationChallngeResponse, trigger the browser to sign it and generate a RegisterPublicKeyCredential
pub async fn create_register_public_key_credential(
    ccr: webauthn_rs_proto::CreationChallengeResponse,
) -> Result<RegisterPublicKeyCredential, WebauthnClientError> {
    // First, convert from our webauthn proto json safe format, into the browser
    // compatible struct, with everything decoded as needed.
    let c_options: web_sys::CredentialCreationOptions = ccr.into();

    // Create a promise that calls the browsers navigator.credentials.create api.
    let window = web_sys::window().ok_or(WebauthnClientError::WindowError)?;
    let promise = window
        .navigator()
        .credentials()
        .create_with_options(&c_options)
        .expect_throw("Unable to create promise");

    let fut = JsFuture::from(promise);

    // Wait on the promise, when complete it will issue a callback.
    match fut.await {
        Ok(jsval) => {
            // Convert from the raw js value into the expected PublicKeyCredential
            let w_rpkc = web_sys::PublicKeyCredential::from(jsval);
            // Serialise the web_sys::pkc into the webauthn proto version, ready to
            // handle/transmit.
            let rpkc = RegisterPublicKeyCredential::from(w_rpkc);
            // start the fetch routine to post to the server
            Ok(rpkc)
        }
        Err(e) => {
            console::log!(format!("error -> {:?}", e).as_str());
            // AppMsg::Error(format!("{:?}", e))
            Err(WebauthnClientError::CreatePublicKeyCredentialError(
                format!("{:?}", e),
            ))
        }
    }
}

// Once the browser has generated a Public Key with an authenticator, it needs to send a
// RegisterPublicKeyCredential to the server.
pub async fn send_register_public_key_credential(
    rpkc: RegisterPublicKeyCredential,
    finish_register_url: &str,
) -> Result<(), WebauthnClientError> {
    console::log!(format!("rpkc -> {:?}", rpkc).as_str());

    let req_jsvalue = serde_json::to_string(&rpkc)
        .map(|s| JsValue::from(&s))
        .expect("Failed to serialise rpkc");

    let mut opts = RequestInit::new();
    opts.method("POST");
    opts.mode(RequestMode::Cors);
    opts.body(Some(&req_jsvalue));
    opts.credentials(RequestCredentials::Include);

    //default is format!("/register_finish/{}", user_name)
    let request = Request::new_with_str_and_init(finish_register_url, &opts)
        .map_err(|_| WebauthnClientError::ChallengeRequestError)?;
    request
        .headers()
        .set("content-type", "application/json")
        .expect_throw("failed to set header");

    let window = web_sys::window().ok_or(WebauthnClientError::WindowError)?;
    let resp_value = JsFuture::from(window.fetch_with_request(&request))
        .await
        .map_err(|_| WebauthnClientError::ChallengeResponseError)?;
    let resp: Response = resp_value.dyn_into().unwrap_throw();
    let status = resp.status();

    if status == 200 {
        Ok(())
    } else {
        let text = JsFuture::from(resp.text().expect("Unable to get error!"))
            .await
            .expect("Unable to convert error into future");
        let emsg = text
            .as_string()
            .unwrap_or_else(|| "Unable to get error!".to_string());
        Err(WebauthnClientError::RegisterPublicKeyError(emsg))
    }
}

// These functions refer to the login process

#[wasm_bindgen]
pub async fn process_login(
    tenant_name: String,
    user_name: String,
    start_login_url: String,
    finish_login_url: String,
) -> Result<JsValue, JsError> {
    // Get RequestChallengeResponse from the server
    let rcr = get_request_challenge_response(&tenant_name, &user_name, &start_login_url).await?;
    // Trigger the browser to sign it
    let pkc = get_public_key_credential(rcr).await?;
    // Send it to the server for final verification
    let authorization_code =
        JsValue::from_serde(&send_public_key_credential(pkc, &finish_login_url).await?)?;

    Ok(authorization_code)
}

/// The browser will receive a RequestChallengeResponse that needs to be passed to the browser
/// API so the authenticator can sign it.
pub async fn get_request_challenge_response(
    tenant_name: &str,
    user_name: &str,
    start_login_url: &str,
) -> Result<RequestChallengeResponse, WebauthnClientError> {
    let mut opts = RequestInit::new();
    opts.method("POST");
    opts.mode(RequestMode::Cors);
    opts.credentials(RequestCredentials::Include);

    //default is format!("/login_start/{}", user_name)
    let dest = format!("{}/{}/{}", start_login_url, tenant_name, user_name);
    let request = Request::new_with_str_and_init(&dest, &opts)
        .map_err(|_| WebauthnClientError::ChallengeRequestError)?;

    request
        .headers()
        .set("content-type", "application/json")
        .expect_throw("failed to set header");

    let window = web_sys::window().ok_or(WebauthnClientError::WindowError)?;
    let resp_value = JsFuture::from(window.fetch_with_request(&request))
        .await
        .map_err(|_| WebauthnClientError::FutureError)?;
    let resp: Response = resp_value.dyn_into().unwrap_throw();
    let status = resp.status();

    if status == 200 {
        let jsval = JsFuture::from(
            resp.json()
                .map_err(|_| WebauthnClientError::ResponseParseError)?,
        )
        .await
        .map_err(|_| WebauthnClientError::ResponseParseError)?;
        let rcr: RequestChallengeResponse = jsval.into_serde().unwrap_throw();
        Ok(rcr)
    } else {
        let text = JsFuture::from(
            resp.text()
                .map_err(|_| WebauthnClientError::ResponseParseError)?,
        )
        .await
        .map_err(|_| WebauthnClientError::FutureError)?;
        let emsg = text
            .as_string()
            .unwrap_or_else(|| "No message provided".to_string());
        Err(WebauthnClientError::WebauthnServerLoginError(emsg))
    }
}
/// Once the browser has generated a Public Key with an authenticator, it needs to generate a
/// PublicKeyCredential to the server for it to complete login
pub async fn get_public_key_credential(
    rcr: RequestChallengeResponse,
) -> Result<PublicKeyCredential, WebauthnClientError> {
    let c_options: web_sys::CredentialRequestOptions = rcr.into();

    let window = web_sys::window().ok_or(WebauthnClientError::WindowError)?;
    let promise = window
        .navigator()
        .credentials()
        .get_with_options(&c_options)
        .expect_throw("Unable to create promise");
    let fut = JsFuture::from(promise);
    // Wait on the promise, when complete it will issue a callback.
    match fut.await {
        Ok(jsval) => {
            let w_rpkc = web_sys::PublicKeyCredential::from(jsval);
            // Serialise the web_sys::pkc into the webauthn proto version, ready to
            // handle/transmit.
            let pkc = PublicKeyCredential::from(w_rpkc);
            // start the fetch routine to post to the server
            Ok(pkc)
        }
        Err(e) => {
            console::log!(format!("error -> {:?}", e).as_str());
            Err(WebauthnClientError::WebauthnServerLoginError(format!(
                "{:?}",
                e
            )))
        }
    }
}

#[derive(Serialize, Deserialize, Debug)]
pub struct AuthorizationCode {
    pub authorization_code: String,
}

/// Once the browser has generated a Public Key with an authenticator, it needs to send a
/// PublicKeyCredential to the server for it to complete login
pub async fn send_public_key_credential(
    pkc: PublicKeyCredential,
    finish_login_url: &str,
) -> Result<AuthorizationCode, WebauthnClientError> {
    console::log!(format!("pkc -> {:?}", pkc).as_str());

    let req_jsvalue = serde_json::to_string(&pkc)
        .map(|s| JsValue::from(&s))
        .expect("Failed to serialise pkc");

    let mut opts = RequestInit::new();
    opts.method("POST");
    opts.mode(RequestMode::Cors);
    opts.body(Some(&req_jsvalue));
    opts.credentials(RequestCredentials::Include);

    //default is format!("/login_finish/{}", user_name)
    let request = Request::new_with_str_and_init(finish_login_url, &opts)
        .map_err(|_| WebauthnClientError::KeyRequestError)?;
    request
        .headers()
        .set("content-type", "application/json")
        .expect_throw("failed to set header");

    let window = web_sys::window().ok_or(WebauthnClientError::WindowError)?;
    let resp_value = JsFuture::from(window.fetch_with_request(&request))
        .await
        .map_err(|_| WebauthnClientError::KeyResponseError)?;
    let resp: Response = resp_value.dyn_into().unwrap_throw();
    let status = resp.status();

    if status == 200 {
        console::log!("Login successful! Got Authorization Code");
        let jsval = JsFuture::from(
            resp.json()
                .map_err(|_| WebauthnClientError::ResponseParseError)?,
        )
        .await
        .map_err(|_| WebauthnClientError::ResponseParseError)?;
        let authorization_code: AuthorizationCode = jsval.into_serde().unwrap_throw();
        Ok(authorization_code)
    } else {
        let text = JsFuture::from(
            resp.text()
                .map_err(|_| WebauthnClientError::ResponseParseError)?,
        )
        .await
        .map_err(|_| WebauthnClientError::FutureError)?;
        let emsg = text.as_string().unwrap_or_default();
        Err(WebauthnClientError::WebauthnServerLoginError(emsg))
    }
}

#[derive(Serialize, Deserialize, Debug)]
pub struct Tokens {
    pub access_token: String,
    pub refresh_token: String,
}
/// Once the browser has generated a Public Key with an authenticator, it needs to send a
/// PublicKeyCredential to the server for it to complete login
pub async fn get_tokens(
    authorization_code: &str,
    authorization_url: &str,
) -> Result<Tokens, WebauthnClientError> {
    let mut opts = RequestInit::new();
    opts.method("POST");
    opts.mode(RequestMode::Cors);
    opts.body(None);
    opts.credentials(RequestCredentials::Include);

    //default is format!("/login_finish/{}", user_name)
    let request = Request::new_with_str_and_init(
        &format!("{}/{}", authorization_url, authorization_code),
        &opts,
    )
    .map_err(|_| WebauthnClientError::KeyRequestError)?;
    request
        .headers()
        .set("content-type", "application/json")
        .expect_throw("failed to set header");

    let window = web_sys::window().ok_or(WebauthnClientError::WindowError)?;
    let resp_value = JsFuture::from(window.fetch_with_request(&request))
        .await
        .map_err(|_| WebauthnClientError::KeyResponseError)?;
    let resp: Response = resp_value.dyn_into().unwrap_throw();
    let status = resp.status();

    if status == 200 {
        console::log!("Got Tokens!");
        let jsval = JsFuture::from(
            resp.json()
                .map_err(|_| WebauthnClientError::ResponseParseError)?,
        )
        .await
        .map_err(|_| WebauthnClientError::ResponseParseError)?;
        let tokens: Tokens = jsval.into_serde().unwrap_throw();
        Ok(tokens)
    } else {
        let text = JsFuture::from(
            resp.text()
                .map_err(|_| WebauthnClientError::ResponseParseError)?,
        )
        .await
        .map_err(|_| WebauthnClientError::FutureError)?;
        let emsg = text.as_string().unwrap_or_default();
        Err(WebauthnClientError::AuthorizationError(emsg))
    }
}
