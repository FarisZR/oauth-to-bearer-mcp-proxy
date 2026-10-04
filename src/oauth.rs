use std::{
    collections::HashMap,
    sync::Arc,
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

use axum::{
    Json,
    extract::{Form, Query, State},
    http::{HeaderMap, StatusCode, header},
    response::{Html, IntoResponse, Redirect, Response},
};
use base64::{
    Engine,
    engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD},
};
use serde::{Deserialize, Serialize};
use serde_json::json;
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;
use url::Url;

use crate::{App, config::validate_redirects, crypto::random_id};

const PENDING_TTL: Duration = Duration::from_secs(600);
const CODE_TTL: Duration = Duration::from_secs(120);
const MAX_CODES: usize = 1024;
const CODE_BURST: usize = 32;
const CODES_PER_SECOND: u32 = 2;
const _: () =
    assert!(CODE_BURST + CODE_TTL.as_secs() as usize * (CODES_PER_SECOND as usize) < MAX_CODES);

pub(crate) struct OAuthError(StatusCode, &'static str, &'static str);

impl OAuthError {
    fn invalid(message: &'static str) -> Self {
        Self(StatusCode::BAD_REQUEST, "invalid_request", message)
    }

    fn client() -> Self {
        Self(
            StatusCode::UNAUTHORIZED,
            "invalid_client",
            "Client authentication failed",
        )
    }

    fn grant() -> Self {
        Self(
            StatusCode::BAD_REQUEST,
            "invalid_grant",
            "Authorization code is invalid or expired",
        )
    }

    fn busy() -> Self {
        Self(
            StatusCode::SERVICE_UNAVAILABLE,
            "temporarily_unavailable",
            "Authorization is temporarily unavailable; try again later",
        )
    }

    fn limited() -> Self {
        Self(
            StatusCode::TOO_MANY_REQUESTS,
            "temporarily_unavailable",
            "Too many authorizations; retry after one second",
        )
    }
}

impl IntoResponse for OAuthError {
    fn into_response(self) -> Response {
        let mut response = (
            self.0,
            Json(json!({"error": self.1, "error_description": self.2})),
        )
            .into_response();
        if self.0 == StatusCode::UNAUTHORIZED {
            response.headers_mut().insert(
                header::WWW_AUTHENTICATE,
                "Basic realm=\"oauth/token\"".parse().unwrap(),
            );
        }
        if self.0 == StatusCode::TOO_MANY_REQUESTS {
            response
                .headers_mut()
                .insert(header::RETRY_AFTER, "1".parse().unwrap());
        }
        private(response)
    }
}

/// Never cache credentials, forms, authorization redirects, or token errors.
fn private(mut response: Response) -> Response {
    for (name, value) in [
        ("cache-control", "no-store"),
        ("pragma", "no-cache"),
        ("referrer-policy", "no-referrer"),
        ("x-content-type-options", "nosniff"),
        ("x-frame-options", "DENY"),
        (
            "content-security-policy",
            "default-src 'none'; style-src 'unsafe-inline'; form-action 'self'; base-uri 'none'; frame-ancestors 'none'",
        ),
    ] {
        response.headers_mut().insert(
            name.parse::<axum::http::HeaderName>().unwrap(),
            value.parse().unwrap(),
        );
    }
    response
}

pub(crate) async fn resource_metadata(State(app): State<Arc<App>>) -> Json<serde_json::Value> {
    Json(json!({
        "resource": app.config.resource(),
        "resource_name": app.config.name,
        "authorization_servers": [app.config.issuer()],
        "bearer_methods_supported": ["header"]
    }))
}

pub(crate) async fn server_metadata(State(app): State<Arc<App>>) -> Json<serde_json::Value> {
    let issuer = app.config.issuer();
    Json(json!({
        "issuer": issuer,
        "authorization_endpoint": format!("{issuer}/oauth/authorize"),
        "token_endpoint": format!("{issuer}/oauth/token"),
        "registration_endpoint": format!("{issuer}/oauth/register"),
        "response_types_supported": ["code"],
        "response_modes_supported": ["query"],
        "grant_types_supported": ["authorization_code"],
        "token_endpoint_auth_methods_supported": ["none", "client_secret_basic", "client_secret_post"],
        "code_challenge_methods_supported": ["S256"],
        "authorization_response_iss_parameter_supported": true,
        "client_id_metadata_document_supported": false
    }))
}

#[derive(Clone, Serialize, Deserialize)]
struct Client {
    redirect_uris: Vec<String>,
    name: String,
    method: String,
    secret: Option<String>,
}

#[derive(Deserialize)]
pub(crate) struct Registration {
    redirect_uris: Vec<String>,
    client_name: Option<String>,
    token_endpoint_auth_method: Option<String>,
    grant_types: Option<Vec<String>>,
    response_types: Option<Vec<String>>,
}

pub(crate) async fn register(
    State(app): State<Arc<App>>,
    Json(registration): Json<Registration>,
) -> Result<Response, OAuthError> {
    validate_redirects(&registration.redirect_uris).map_err(|_| {
        OAuthError(
            StatusCode::BAD_REQUEST,
            "invalid_redirect_uri",
            "Use exact HTTPS or loopback HTTP callback URLs",
        )
    })?;
    if registration.redirect_uris.is_empty() {
        return Err(OAuthError::invalid("At least one redirect_uri is required"));
    }
    let method = registration
        .token_endpoint_auth_method
        .unwrap_or_else(|| "client_secret_basic".into());
    if !matches!(
        method.as_str(),
        "none" | "client_secret_basic" | "client_secret_post"
    ) || registration.grant_types.as_ref().is_some_and(|types| {
        !types.iter().any(|t| t == "authorization_code")
            || types
                .iter()
                .any(|t| t != "authorization_code" && t != "refresh_token")
    }) || registration
        .response_types
        .as_ref()
        .is_some_and(|types| types != &["code"])
    {
        return Err(OAuthError(
            StatusCode::BAD_REQUEST,
            "invalid_client_metadata",
            "Only authorization_code with S256 PKCE is supported",
        ));
    }
    let name = registration
        .client_name
        .unwrap_or_else(|| "MCP client".into());
    if name.is_empty() || name.len() > 200 {
        return Err(OAuthError::invalid("client_name must have 1 to 200 bytes"));
    }
    let client = Client {
        redirect_uris: registration.redirect_uris,
        name,
        secret: (method != "none").then(random_id),
        method,
    };
    // A sealed registration is its own opaque client ID: no client database,
    // no expiry, and no lost registrations when the container restarts.
    let client_id = format!(
        "dcr_{}",
        app.sealer
            .seal("client", &client)
            .map_err(|_| OAuthError::busy())?
    );
    let mut response = json!({
        "client_id": client_id,
        "client_id_issued_at": SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs(),
        "client_name": client.name,
        "redirect_uris": client.redirect_uris,
        "token_endpoint_auth_method": client.method,
        "grant_types": ["authorization_code"],
        "response_types": ["code"]
    });
    if let Some(secret) = client.secret {
        response["client_secret"] = json!(secret);
        response["client_secret_expires_at"] = json!(0);
    }
    Ok(private(
        (StatusCode::CREATED, Json(response)).into_response(),
    ))
}

fn client(app: &App, id: &str) -> Result<Client, OAuthError> {
    if app.config.oauth.client_id.as_deref() == Some(id) {
        return Ok(Client {
            redirect_uris: app.config.oauth.redirect_uris.clone(),
            name: "MCP client".into(),
            method: "api_key".into(),
            secret: None,
        });
    }
    id.strip_prefix("dcr_")
        .and_then(|value| app.sealer.open("client", value))
        .ok_or_else(OAuthError::client)
}

#[derive(Clone, Serialize, Deserialize)]
pub(crate) struct Authorization {
    response_type: String,
    client_id: String,
    redirect_uri: String,
    state: Option<String>,
    code_challenge: Option<String>,
    code_challenge_method: Option<String>,
    resource: Option<String>,
    scope: Option<String>,
}

#[derive(Serialize, Deserialize)]
struct Pending {
    request: Authorization,
    nonce: String,
    expires: u64,
}

pub(crate) struct Code {
    request: Authorization,
    api_key: Option<String>,
    created: Instant,
}

pub(crate) struct Codes {
    entries: HashMap<String, Code>,
    credit: f64,
    updated: Instant,
}

impl Codes {
    pub(crate) fn new() -> Self {
        Self {
            entries: HashMap::new(),
            credit: CODE_BURST as f64,
            updated: Instant::now(),
        }
    }

    fn issue(
        &mut self,
        request: Authorization,
        api_key: Option<String>,
    ) -> Result<String, OAuthError> {
        let now = Instant::now();
        self.credit = (self.credit
            + now.duration_since(self.updated).as_secs_f64() * f64::from(CODES_PER_SECOND))
        .min(CODE_BURST as f64);
        self.updated = now;
        self.entries
            .retain(|_, entry| now.duration_since(entry.created) < CODE_TTL);
        // A burst plus all replenishment during CODE_TTL fits well below the
        // storage cap (32 + 2 * 120 = 272). DCR identities cannot evade this
        // instance-wide budget. A burst cannot reserve every slot for 120s.
        if self.credit < 1.0 {
            return Err(OAuthError::limited());
        }
        if self.entries.len() >= MAX_CODES {
            return Err(OAuthError::busy());
        }
        self.credit -= 1.0;
        let code = random_id();
        self.entries.insert(
            code.clone(),
            Code {
                request,
                api_key,
                created: now,
            },
        );
        Ok(code)
    }
}

fn resource(app: &App, value: Option<&str>) -> Result<(), OAuthError> {
    if value.is_some_and(|value| {
        Url::parse(value).ok().as_ref() != Some(&Url::parse(&app.config.resource()).unwrap())
    }) {
        return Err(OAuthError(
            StatusCode::BAD_REQUEST,
            "invalid_target",
            "resource must identify this MCP endpoint",
        ));
    }
    Ok(())
}

fn authorization_parameters(app: &App, request: &Authorization) -> Result<(), OAuthError> {
    if request.response_type != "code" {
        return Err(OAuthError(
            StatusCode::BAD_REQUEST,
            "unsupported_response_type",
            "Use the authorization code flow",
        ));
    }
    if request.code_challenge_method.as_deref() != Some("S256")
        || !request.code_challenge.as_ref().is_some_and(|c| {
            c.len() == 43
                && URL_SAFE_NO_PAD
                    .decode(c)
                    .is_ok_and(|bytes| bytes.len() == 32)
        })
    {
        return Err(OAuthError::invalid("S256 PKCE is required"));
    }
    if request.state.as_ref().is_some_and(|s| s.len() > 2048)
        || request.scope.as_ref().is_some_and(|s| {
            s.len() > 1024
                || !s
                    .bytes()
                    .all(|b| matches!(b, b' ' | 0x21 | 0x23..=0x5b | 0x5d..=0x7e))
        })
    {
        return Err(OAuthError::invalid("Invalid state or scope"));
    }
    resource(app, request.resource.as_deref())
}

pub(crate) async fn authorize(
    State(app): State<Arc<App>>,
    Query(request): Query<Authorization>,
) -> Result<Response, OAuthError> {
    let client = client(&app, &request.client_id)?;
    // Never redirect an error to an unregistered or loosely matched callback.
    if !client.redirect_uris.contains(&request.redirect_uri) {
        return Err(OAuthError::invalid(
            "redirect_uri is not registered for this client",
        ));
    }
    if let Err(error) = authorization_parameters(&app, &request) {
        return Ok(callback(&app, &request, None, Some(error.1)));
    }
    let callback_origin = Url::parse(&request.redirect_uri)
        .unwrap()
        .origin()
        .ascii_serialization();
    let nonce = random_id();
    // Merely opening a form reserves no shared state. The authenticated ticket
    // carries the validated parameters; the short cookie still binds the browser.
    let ticket = app
        .sealer
        .seal(
            "consent",
            &Pending {
                request,
                nonce: nonce.clone(),
                expires: SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .unwrap()
                    .as_secs()
                    + PENDING_TTL.as_secs(),
            },
        )
        .map_err(|_| OAuthError::busy())?;
    let key_field = if client.method == "api_key" {
        "<p>Your client will supply the API token through its OAuth client secret.</p>".to_owned()
    } else {
        "<p>Enter your API token to connect this client.</p><label for=api_token>API token</label><input id=api_token name=api_token type=password autocomplete=off required maxlength=4096>".to_owned()
    };
    let authorize_path = app.config.endpoint_path("/oauth/authorize");
    let html = format!(
        "<!doctype html><html lang=en><meta charset=utf-8><meta name=viewport content=\"width=device-width,initial-scale=1\"><title>Connect to {name}</title><style>body{{font:16px system-ui;background:#f5f5f5;color:#202020;margin:0;padding:2rem}}main{{max-width:28rem;margin:8vh auto;background:white;padding:2rem;border-radius:12px}}h1{{font-size:1.5rem}}label,input{{display:block;width:100%;box-sizing:border-box}}input{{padding:.75rem;margin:.5rem 0 1rem;border:1px solid #888;border-radius:6px}}button{{padding:.7rem 1rem;margin-right:.5rem;cursor:pointer}}</style><main><h1>Connect to {name}</h1><p>Allow <strong>{client}</strong> to use this MCP server with your API token.</p><form action=\"{authorize_path}\" method=post><input type=hidden name=ticket value=\"{ticket}\">{key_field}<button type=submit name=action value=allow>Connect</button><button type=submit name=action value=deny formnovalidate>Cancel</button></form></main></html>",
        name = escape(&app.config.name),
        client = escape(&client.name),
    );
    let mut response = private(Html(html).into_response());
    // Browsers may apply form-action to the redirect after a form submission.
    // Permit the validated callback origin as well as this same-origin form.
    response.headers_mut().insert(header::CONTENT_SECURITY_POLICY,
        format!("default-src 'none'; style-src 'unsafe-inline'; form-action 'self' {callback_origin}; base-uri 'none'; frame-ancestors 'none'").parse().unwrap());
    response.headers_mut().insert(
        header::SET_COOKIE,
        cookie(&app, &nonce, false).parse().unwrap(),
    );
    Ok(response)
}

fn escape(value: &str) -> String {
    value
        .replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&#39;")
}

fn cookie(app: &App, ticket: &str, clear: bool) -> String {
    format!(
        "mcp_oauth_{ticket}={}; Path={}; Max-Age={}; HttpOnly; SameSite=Lax{}",
        if clear { "" } else { ticket },
        app.config.endpoint_path("/oauth/authorize"),
        if clear { 0 } else { PENDING_TTL.as_secs() },
        if app.config.public_url.scheme() == "https" {
            "; Secure"
        } else {
            ""
        }
    )
}

fn has_cookie(headers: &HeaderMap, ticket: &str) -> bool {
    let expected = format!("mcp_oauth_{ticket}={ticket}");
    headers
        .get_all(header::COOKIE)
        .iter()
        .filter_map(|value| value.to_str().ok())
        .flat_map(|value| value.split(';'))
        .any(|cookie| cookie.trim() == expected)
}

#[derive(Deserialize)]
pub(crate) struct Consent {
    ticket: String,
    api_token: Option<String>,
    action: String,
}

pub(crate) async fn consent(
    State(app): State<Arc<App>>,
    headers: HeaderMap,
    Form(form): Form<Consent>,
) -> Result<Response, OAuthError> {
    let entry: Pending = app.sealer.open("consent", &form.ticket).ok_or_else(|| {
        OAuthError::invalid("Authorization form is invalid or expired; reconnect your client")
    })?;
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs();
    if entry.expires <= now || entry.expires > now + PENDING_TTL.as_secs() {
        return Err(OAuthError::invalid(
            "Authorization form expired; reconnect your client",
        ));
    }
    if !has_cookie(&headers, &entry.nonce)
        || headers
            .get(header::ORIGIN)
            .is_some_and(|v| v.to_str().ok() != Some(app.config.origin().as_str()))
    {
        return Err(OAuthError::invalid(
            "Authorization form must be submitted from the same browser",
        ));
    }
    if !matches!(form.action.as_str(), "allow" | "deny") {
        return Err(OAuthError::invalid("Invalid consent action"));
    }
    let client = client(&app, &entry.request.client_id)?;
    // Stateless forms survive restarts; a changed callback allowlist still wins.
    if !client.redirect_uris.contains(&entry.request.redirect_uri) {
        return Err(OAuthError::invalid(
            "redirect_uri is not registered for this client",
        ));
    }
    let api_key = if form.action == "allow" && client.method != "api_key" {
        let key = form
            .api_token
            .ok_or_else(|| OAuthError::invalid("API token is required"))?;
        if !valid_api_key(&key) {
            return Err(OAuthError::invalid(
                "Paste the raw API token, without Bearer, whitespace, or control characters",
            ));
        }
        Some(key)
    } else {
        None
    };
    let mut response = if form.action == "deny" {
        callback(&app, &entry.request, None, Some("access_denied"))
    } else {
        let mut codes = app.codes.lock().unwrap();
        let code = codes.issue(entry.request.clone(), api_key)?;
        callback(&app, &entry.request, Some(&code), None)
    };
    response.headers_mut().insert(
        header::SET_COOKIE,
        cookie(&app, &entry.nonce, true).parse().unwrap(),
    );
    Ok(response)
}

fn callback(
    app: &App,
    request: &Authorization,
    code: Option<&str>,
    error: Option<&str>,
) -> Response {
    let mut url = Url::parse(&request.redirect_uri).unwrap();
    {
        let mut pairs = url.query_pairs_mut();
        if let Some(code) = code {
            pairs.append_pair("code", code);
        }
        if let Some(error) = error {
            pairs.append_pair("error", error);
        }
        if let Some(state) = &request.state {
            pairs.append_pair("state", state);
        }
        pairs.append_pair("iss", &app.config.issuer());
    }
    private(Redirect::to(url.as_str()).into_response())
}

#[derive(Deserialize)]
pub(crate) struct TokenRequest {
    grant_type: String,
    code: Option<String>,
    redirect_uri: Option<String>,
    client_id: Option<String>,
    client_secret: Option<String>,
    code_verifier: Option<String>,
    resource: Option<String>,
}

fn decode_basic_component(value: &str) -> String {
    url::form_urlencoded::parse(format!("v={value}").as_bytes())
        .next()
        .unwrap()
        .1
        .into_owned()
}

fn credentials(
    headers: &HeaderMap,
    form: &TokenRequest,
) -> Result<(String, Option<String>, &'static str), OAuthError> {
    if headers.get_all(header::AUTHORIZATION).iter().count() > 1 {
        return Err(OAuthError::client());
    }
    if let Some(auth) = headers.get(header::AUTHORIZATION) {
        if form.client_secret.is_some() {
            return Err(OAuthError::client());
        }
        let value = auth.to_str().map_err(|_| OAuthError::client())?;
        let (scheme, data) = value.split_once(' ').ok_or_else(OAuthError::client)?;
        if !scheme.eq_ignore_ascii_case("Basic") {
            return Err(OAuthError::client());
        }
        let data = STANDARD.decode(data).map_err(|_| OAuthError::client())?;
        let data = String::from_utf8(data).map_err(|_| OAuthError::client())?;
        let (id, secret) = data.split_once(':').ok_or_else(OAuthError::client)?;
        let id = decode_basic_component(id);
        if form
            .client_id
            .as_ref()
            .is_some_and(|body_id| body_id != &id)
        {
            return Err(OAuthError::client());
        }
        Ok((
            id,
            Some(decode_basic_component(secret)),
            "client_secret_basic",
        ))
    } else {
        Ok((
            form.client_id.clone().ok_or_else(OAuthError::client)?,
            form.client_secret.clone(),
            if form.client_secret.is_some() {
                "client_secret_post"
            } else {
                "none"
            },
        ))
    }
}

pub(crate) async fn token(
    State(app): State<Arc<App>>,
    headers: HeaderMap,
    Form(form): Form<TokenRequest>,
) -> Result<Response, OAuthError> {
    if form.grant_type != "authorization_code" {
        return Err(OAuthError(
            StatusCode::BAD_REQUEST,
            "unsupported_grant_type",
            "Only authorization_code is supported",
        ));
    }
    resource(&app, form.resource.as_deref())?;
    let (id, supplied_secret, method) = credentials(&headers, &form)?;
    let client = client(&app, &id)?;
    let manual_key = if client.method == "api_key" {
        let key = supplied_secret.ok_or_else(OAuthError::client)?;
        if !valid_api_key(&key) {
            return Err(OAuthError::client());
        }
        Some(key)
    } else {
        if client.method != method
            || match (&client.secret, &supplied_secret) {
                (None, None) => false,
                (Some(expected), Some(actual)) => {
                    !bool::from(expected.as_bytes().ct_eq(actual.as_bytes()))
                }
                _ => true,
            }
        {
            return Err(OAuthError::client());
        }
        None
    };
    let code = form.code.as_ref().ok_or_else(OAuthError::grant)?;
    let verifier = form.code_verifier.as_ref().ok_or_else(OAuthError::grant)?;
    if !(43..=128).contains(&verifier.len())
        || !verifier
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"-._~".contains(&b))
    {
        return Err(OAuthError::grant());
    }
    let challenge = URL_SAFE_NO_PAD.encode(Sha256::digest(verifier.as_bytes()));
    let mut codes = app.codes.lock().unwrap();
    codes
        .entries
        .retain(|_, entry| entry.created.elapsed() < CODE_TTL);
    let entry = codes.entries.get(code).ok_or_else(OAuthError::grant)?;
    if entry.request.client_id != id
        || Some(entry.request.redirect_uri.as_str()) != form.redirect_uri.as_deref()
        || !bool::from(
            entry
                .request
                .code_challenge
                .as_deref()
                .unwrap()
                .as_bytes()
                .ct_eq(challenge.as_bytes()),
        )
    {
        return Err(OAuthError::grant());
    }
    // Consume under one lock so simultaneous exchanges cannot reuse a code.
    let entry = codes.entries.remove(code).unwrap();
    drop(codes);
    let key = manual_key.or(entry.api_key).ok_or_else(OAuthError::grant)?;
    let access_token = app
        .sealer
        .seal("access", &key)
        .map_err(|_| OAuthError::busy())?;
    let mut response = json!({"access_token": access_token, "token_type": "Bearer"});
    if let Some(scope) = entry.request.scope {
        response["scope"] = json!(scope);
    }
    // The upstream controls API-key expiry. An OAuth token has the same lifetime;
    // omitting expires_in is valid and avoids unnecessary refresh-token machinery.
    Ok(private(Json(response).into_response()))
}

pub(crate) fn valid_api_key(key: &str) -> bool {
    !key.is_empty() && key.len() <= 4096 && key.bytes().all(|byte| (0x21..=0x7e).contains(&byte))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn basic_credentials_decode_oauth_form_encoding() {
        let mut headers = HeaderMap::new();
        headers.insert(
            header::AUTHORIZATION,
            format!("Basic {}", STANDARD.encode("client%3Aid:key%2B%2F%3D"))
                .parse()
                .unwrap(),
        );
        let form = TokenRequest {
            grant_type: "authorization_code".into(),
            code: None,
            redirect_uri: None,
            client_id: None,
            client_secret: None,
            code_verifier: None,
            resource: None,
        };
        let (id, secret, method) = credentials(&headers, &form)
            .unwrap_or_else(|_| panic!("valid Basic credentials rejected"));
        assert_eq!(id, "client:id");
        assert_eq!(secret.as_deref(), Some("key+/="));
        assert_eq!(method, "client_secret_basic");
    }
}
