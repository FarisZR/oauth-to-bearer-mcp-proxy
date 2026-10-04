use std::{
    convert::Infallible,
    sync::{Arc, Mutex},
    time::Duration,
};

use axum::{
    Router,
    body::{Body, Bytes, to_bytes},
    extract::{Request, State},
    http::{HeaderMap, StatusCode, header},
    response::{IntoResponse, Response},
    routing::any,
};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use oauth_to_key_mcp_proxy::{
    config::{Config, Limits},
    router, serve,
};
use reqwest::Client;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use tempfile::TempDir;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::task::JoinHandle;
use url::Url;

const KEY: &str = "test-upstream-key+/=";
const VERIFIER: &str = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUV";
const CALLBACK: &str = "https://client.example/callback?keep=1";

struct Server {
    url: String,
    task: JoinHandle<()>,
}

impl Server {
    async fn start(app: Router) -> Self {
        Self::start_with_limits(app, Limits::default()).await
    }

    async fn start_with_limits(app: Router, limits: Limits) -> Self {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!("http://{}", listener.local_addr().unwrap());
        let task = tokio::spawn(async {
            serve(listener, app, limits, std::future::pending())
                .await
                .unwrap()
        });
        Self { url, task }
    }
}

impl Drop for Server {
    fn drop(&mut self) {
        self.task.abort();
    }
}

struct Captured {
    method: String,
    query: String,
    headers: HeaderMap,
    body: Bytes,
}

type Captures = Arc<Mutex<Vec<Captured>>>;

async fn upstream(State(captures): State<Captures>, request: Request) -> Response {
    let (parts, body) = request.into_parts();
    let kind = parts
        .headers
        .get("x-test-response")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("json")
        .to_owned();
    let valid = parts
        .headers
        .get(header::AUTHORIZATION)
        .is_some_and(|v| v == format!("Bearer {KEY}").as_str());
    let body = to_bytes(body, 8 * 1024 * 1024).await.unwrap();
    captures.lock().unwrap().push(Captured {
        method: parts.method.to_string(),
        query: parts.uri.query().unwrap_or_default().to_owned(),
        headers: parts.headers,
        body,
    });
    if !valid || kind == "unauthorized" {
        return (
            StatusCode::UNAUTHORIZED,
            [("www-authenticate", "Bearer realm=\"upstream\"")],
            "upstream rejected key",
        )
            .into_response();
    }
    if kind == "redirect" {
        return (
            StatusCode::TEMPORARY_REDIRECT,
            [("location", "http://127.0.0.1:1/leak")],
        )
            .into_response();
    }
    if kind == "timeout" {
        tokio::time::sleep(Duration::from_millis(1300)).await;
    }
    if kind == "sse" {
        let stream = futures_util::stream::unfold(0, |index| async move {
            match index {
                0 => Some((
                    Ok::<_, Infallible>(Bytes::from_static(
                        b"id: 1\nevent: message\ndata: {\"one\":1}\n\n",
                    )),
                    1,
                )),
                1 => {
                    tokio::time::sleep(Duration::from_millis(1200)).await;
                    Some((
                        Ok(Bytes::from_static(
                            b"id: 2\nevent: message\ndata: {\"two\":2}\n\n",
                        )),
                        2,
                    ))
                }
                _ => None,
            }
        });
        let mut response = Response::new(Body::from_stream(stream));
        response
            .headers_mut()
            .insert(header::CONTENT_TYPE, "text/event-stream".parse().unwrap());
        response
            .headers_mut()
            .insert("mcp-session-id", "upstream-session".parse().unwrap());
        return response;
    }
    if kind == "notification" {
        return StatusCode::ACCEPTED.into_response();
    }
    (
        StatusCode::OK,
        [
            ("content-type", "application/json"),
            ("mcp-session-id", "upstream-session"),
            ("connection", "x-hop"),
            ("x-hop", "removed"),
            ("set-cookie", "upstream=secret"),
        ],
        "{\"jsonrpc\":\"2.0\",\"id\":1,\"result\":{\"tools\":[]}}",
    )
        .into_response()
}

struct Harness {
    server: Server,
    _upstream: Server,
    _data: TempDir,
    config: Config,
    captures: Captures,
    http: Client,
}

impl Harness {
    async fn new(manual: bool) -> Self {
        Self::new_at_prefix(manual, "").await
    }

    async fn new_at_prefix(manual: bool, prefix: &str) -> Self {
        Self::new_with_limits(manual, prefix, Limits::default()).await
    }

    async fn new_with_limits(manual: bool, prefix: &str, limits: Limits) -> Self {
        let captures = Arc::new(Mutex::new(Vec::new()));
        let upstream = Server::start(
            Router::new()
                .route("/actual", any(upstream))
                .with_state(captures.clone()),
        )
        .await;
        let data = tempfile::tempdir().unwrap();
        let mut config: Config = toml::from_str(&format!("public_url = 'https://proxy.example'\nupstream_url = '{}/actual?configured=yes'\ntoken_key_file = '{}'\nupstream_header_timeout_seconds = 1\nallowed_origins = ['https://browser.example']\n", upstream.url, data.path().join("token.key").display())).unwrap();
        config.public_url = Url::parse(&format!("https://proxy.example{prefix}")).unwrap();
        config.limits = limits;
        if manual {
            config.oauth.client_id = Some("configured-client".into());
            config.oauth.redirect_uris = vec![CALLBACK.into()];
        }
        let mut server =
            Server::start_with_limits(router(config.clone()).unwrap(), config.limits.clone()).await;
        server.url.push_str(config.prefix());
        let http = Client::builder()
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .unwrap();
        Self {
            server,
            _upstream: upstream,
            _data: data,
            config,
            captures,
            http,
        }
    }

    async fn register(&self, method: &str) -> Value {
        let response = self.http.post(format!("{}/oauth/register", self.server.url))
            .json(&json!({"redirect_uris": [CALLBACK], "client_name": "Test <client>", "token_endpoint_auth_method": method, "grant_types": ["authorization_code", "refresh_token"]}))
            .send().await.unwrap();
        assert_eq!(response.status(), StatusCode::CREATED);
        assert_eq!(response.headers()["cache-control"], "no-store");
        response.json().await.unwrap()
    }

    async fn authorize(&self, id: &str) -> (String, String) {
        let challenge = URL_SAFE_NO_PAD.encode(Sha256::digest(VERIFIER.as_bytes()));
        let response = self
            .http
            .get(format!("{}/oauth/authorize", self.server.url))
            .query(&[
                ("response_type", "code"),
                ("client_id", id),
                ("redirect_uri", CALLBACK),
                ("code_challenge", &challenge),
                ("code_challenge_method", "S256"),
                ("state", "state+/=&"),
                ("resource", &self.config.resource()),
            ])
            .send()
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        assert!(
            response.headers()["set-cookie"]
                .to_str()
                .unwrap()
                .contains(&format!(
                    "Path={};",
                    self.config.endpoint_path("/oauth/authorize")
                ))
        );
        let cookie = response.headers()["set-cookie"]
            .to_str()
            .unwrap()
            .split(';')
            .next()
            .unwrap()
            .to_owned();
        let html = response.text().await.unwrap();
        let ticket = html
            .split("name=ticket value=\"")
            .nth(1)
            .unwrap()
            .split('"')
            .next()
            .unwrap()
            .to_owned();
        assert!(!html.contains("<client>"));
        assert!(!html.contains(KEY));
        assert!(html.contains(&format!(
            "action=\"{}\"",
            self.config.endpoint_path("/oauth/authorize")
        )));
        (ticket, cookie)
    }

    async fn consent(&self, ticket: &str, cookie: &str, key: Option<&str>) -> String {
        let mut form = vec![("ticket", ticket), ("action", "allow")];
        if let Some(key) = key {
            form.push(("api_token", key));
        }
        let response = self
            .http
            .post(format!("{}/oauth/authorize", self.server.url))
            .header("cookie", cookie)
            .header("origin", self.config.origin())
            .form(&form)
            .send()
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::SEE_OTHER);
        assert_eq!(response.headers()["cache-control"], "no-store");
        let url = Url::parse(response.headers()["location"].to_str().unwrap()).unwrap();
        assert!(!url.as_str().contains(KEY));
        let pairs: std::collections::HashMap<_, _> = url.query_pairs().into_owned().collect();
        assert_eq!(pairs["keep"], "1");
        assert_eq!(pairs["state"], "state+/=&");
        assert_eq!(pairs["iss"], self.config.issuer());
        pairs["code"].clone()
    }

    fn token_form(&self, id: &str, code: &str) -> Vec<(String, String)> {
        [
            ("grant_type", "authorization_code"),
            ("client_id", id),
            ("code", code),
            ("redirect_uri", CALLBACK),
            ("code_verifier", VERIFIER),
            ("resource", &self.config.resource()),
        ]
        .map(|(k, v)| (k.into(), v.into()))
        .to_vec()
    }

    async fn access_token(&self, method: &str) -> String {
        let registration = self.register(method).await;
        let id = registration["client_id"].as_str().unwrap();
        let (ticket, cookie) = self.authorize(id).await;
        let code = self.consent(&ticket, &cookie, Some(KEY)).await;
        let mut form = self.token_form(id, &code);
        let mut request = self.http.post(format!("{}/oauth/token", self.server.url));
        if method == "client_secret_basic" {
            request = request.basic_auth(id, registration["client_secret"].as_str());
        } else if method == "client_secret_post" {
            form.push((
                "client_secret".into(),
                registration["client_secret"].as_str().unwrap().into(),
            ));
        }
        let response = request.form(&form).send().await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(response.headers()["cache-control"], "no-store");
        let token: Value = response.json().await.unwrap();
        assert_eq!(token["token_type"], "Bearer");
        assert!(token.get("expires_in").is_none());
        let access = token["access_token"].as_str().unwrap().to_owned();
        assert_ne!(access, KEY);
        assert!(!String::from_utf8_lossy(&URL_SAFE_NO_PAD.decode(&access).unwrap()).contains(KEY));
        let replay = self.http.post(format!("{}/oauth/token", self.server.url));
        let replay = if method == "client_secret_basic" {
            replay.basic_auth(id, registration["client_secret"].as_str())
        } else {
            replay
        };
        let response = replay.form(&form).send().await.unwrap();
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        assert_eq!(
            response.json::<Value>().await.unwrap()["error"],
            "invalid_grant"
        );
        access
    }
}

#[tokio::test]
async fn discovery_and_each_registered_client_auth_method_work() {
    let h = Harness::new(false).await;
    let response = h
        .http
        .post(format!("{}/mcp", h.server.url))
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    assert!(
        response.headers()["www-authenticate"]
            .to_str()
            .unwrap()
            .contains("https://proxy.example/.well-known/oauth-protected-resource/mcp")
    );
    assert!(h.captures.lock().unwrap().is_empty());
    for path in [
        "/.well-known/oauth-protected-resource",
        "/.well-known/oauth-protected-resource/mcp",
    ] {
        let value: Value = h
            .http
            .get(format!("{}{path}", h.server.url))
            .send()
            .await
            .unwrap()
            .json()
            .await
            .unwrap();
        assert_eq!(value["resource"], h.config.resource());
        assert_eq!(value["authorization_servers"], json!([h.config.issuer()]));
    }
    for path in [
        "/.well-known/oauth-authorization-server",
        "/.well-known/openid-configuration",
    ] {
        let value: Value = h
            .http
            .get(format!("{}{path}", h.server.url))
            .send()
            .await
            .unwrap()
            .json()
            .await
            .unwrap();
        assert_eq!(value["code_challenge_methods_supported"], json!(["S256"]));
        assert_eq!(
            value["grant_types_supported"],
            json!(["authorization_code"])
        );
    }
    for method in ["none", "client_secret_basic", "client_secret_post"] {
        let access = h.access_token(method).await;
        let response = h
            .http
            .post(format!("{}/mcp", h.server.url))
            .bearer_auth(access)
            .body("hello")
            .send()
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(
            h.captures.lock().unwrap().last().unwrap().headers["authorization"],
            format!("Bearer {KEY}")
        );
    }
}

#[tokio::test]
async fn manual_client_secret_is_the_upstream_key_for_basic_and_post() {
    let h = Harness::new(true).await;
    for basic in [true, false] {
        let id = "configured-client";
        let (ticket, cookie) = h.authorize(id).await;
        let code = h.consent(&ticket, &cookie, None).await;
        let mut form = h.token_form(id, &code);
        let request = h.http.post(format!("{}/oauth/token", h.server.url));
        let encoded_key: String = url::form_urlencoded::byte_serialize(KEY.as_bytes()).collect();
        let request = if basic {
            request.basic_auth(id, Some(encoded_key))
        } else {
            form.push(("client_secret".into(), KEY.into()));
            request
        };
        let response = request.form(&form).send().await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let value: Value = response.json().await.unwrap();
        let response = h
            .http
            .post(format!("{}/mcp", h.server.url))
            .bearer_auth(value["access_token"].as_str().unwrap())
            .send()
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
    }
}

#[tokio::test]
async fn mcp_bytes_headers_methods_and_queries_pass_through() {
    let h = Harness::new(false).await;
    let access = h.access_token("none").await;
    let body = vec![0xfeu8; 2 * 1024 * 1024];
    let response = h
        .http
        .post(format!("{}/mcp?cursor=a%2Bb", h.server.url))
        .bearer_auth(&access)
        .header("content-type", "application/octet-stream")
        .header("accept", "application/json, text/event-stream")
        .header("mcp-session-id", "session")
        .header("mcp-protocol-version", "2025-06-18")
        .header("origin", "https://browser.example")
        .header("cookie", "client=private")
        .header("x-forwarded-for", "untrusted")
        .header("connection", "x-private")
        .header("x-private", "strip")
        .body(body.clone())
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(response.headers()["mcp-session-id"], "upstream-session");
    assert_eq!(
        response.headers()["access-control-allow-origin"],
        "https://browser.example"
    );
    assert!(!response.headers().contains_key("x-hop"));
    assert!(!response.headers().contains_key("set-cookie"));
    assert_eq!(
        response.text().await.unwrap(),
        "{\"jsonrpc\":\"2.0\",\"id\":1,\"result\":{\"tools\":[]}}"
    );
    for method in [reqwest::Method::GET, reqwest::Method::DELETE] {
        let response = h
            .http
            .request(method, format!("{}/mcp", h.server.url))
            .bearer_auth(&access)
            .header("last-event-id", "42")
            .send()
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
    }
    let captures = h.captures.lock().unwrap();
    let captured = &captures[0];
    assert_eq!(captured.method, "POST");
    assert_eq!(captured.query, "configured=yes&cursor=a%2Bb");
    assert_eq!(captured.body, body);
    assert_eq!(captured.headers["mcp-session-id"], "session");
    assert_eq!(captured.headers["mcp-protocol-version"], "2025-06-18");
    assert_eq!(
        captured.headers["origin"],
        h.config.upstream_url.origin().ascii_serialization()
    );
    for header in ["cookie", "x-forwarded-for", "x-private"] {
        assert!(!captured.headers.contains_key(header));
    }
    assert_eq!(captures[1].method, "GET");
    assert_eq!(captures[2].method, "DELETE");
    assert_eq!(captures[1].headers["last-event-id"], "42");
}

#[tokio::test]
async fn sse_is_streamed_and_does_not_expire_at_the_header_timeout() {
    let h = Harness::new(false).await;
    let access = h.access_token("none").await;
    let mut response = h
        .http
        .get(format!("{}/mcp", h.server.url))
        .bearer_auth(access)
        .header("x-test-response", "sse")
        .send()
        .await
        .unwrap();
    assert_eq!(response.headers()["content-type"], "text/event-stream");
    let first = tokio::time::timeout(Duration::from_millis(500), response.chunk())
        .await
        .unwrap()
        .unwrap()
        .unwrap();
    assert_eq!(first, "id: 1\nevent: message\ndata: {\"one\":1}\n\n");
    let second = response.chunk().await.unwrap().unwrap();
    assert_eq!(second, "id: 2\nevent: message\ndata: {\"two\":2}\n\n");
    assert!(response.chunk().await.unwrap().is_none());
}

#[tokio::test]
async fn bad_oauth_bindings_and_browser_csrf_are_rejected() {
    let h = Harness::new(false).await;
    let registration = h.register("none").await;
    let id = registration["client_id"].as_str().unwrap();
    let (ticket, cookie) = h.authorize(id).await;
    let response = h
        .http
        .post(format!("{}/oauth/authorize", h.server.url))
        .form(&[
            ("ticket", &ticket),
            ("action", &"allow".into()),
            ("api_token", &KEY.into()),
        ])
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    let code = h.consent(&ticket, &cookie, Some(KEY)).await;
    let form = h.token_form(id, &code);
    for (field, wrong) in [
        (
            "code_verifier",
            "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
        ),
        ("redirect_uri", "https://evil.example/callback"),
        ("resource", "https://evil.example/mcp"),
    ] {
        let mut bad = form.clone();
        bad.iter_mut().find(|(k, _)| k == field).unwrap().1 = wrong.into();
        let response = h
            .http
            .post(format!("{}/oauth/token", h.server.url))
            .form(&bad)
            .send()
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    }
    let other = h.register("none").await;
    let mut bad = form.clone();
    bad.iter_mut().find(|(k, _)| k == "client_id").unwrap().1 =
        other["client_id"].as_str().unwrap().into();
    let response = h
        .http
        .post(format!("{}/oauth/token", h.server.url))
        .form(&bad)
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    let response = h
        .http
        .post(format!("{}/oauth/token", h.server.url))
        .form(&form)
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let response = h
        .http
        .get(format!("{}/oauth/authorize", h.server.url))
        .query(&[
            ("response_type", "code"),
            ("client_id", id),
            ("redirect_uri", "https://evil.example/callback"),
        ])
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    assert!(!response.headers().contains_key("location"));
    let response = h
        .http
        .post(format!("{}/oauth/register", h.server.url))
        .json(&json!({"redirect_uris": ["http://evil.example/callback"]}))
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn tokens_and_registrations_survive_restart_and_are_bound_to_the_proxy() {
    let mut h = Harness::new(false).await;
    let registration = h.register("none").await;
    let access = h.access_token("none").await;
    h.server = Server::start(router(h.config.clone()).unwrap()).await;
    let response = h
        .http
        .post(format!("{}/mcp", h.server.url))
        .bearer_auth(&access)
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let _ = h
        .authorize(registration["client_id"].as_str().unwrap())
        .await;
    let mut tampered = access.clone().into_bytes();
    tampered[40] = if tampered[40] == b'A' { b'B' } else { b'A' };
    for invalid in [
        KEY.to_owned(),
        String::from_utf8(tampered).unwrap(),
        registration["client_id"]
            .as_str()
            .unwrap()
            .trim_start_matches("dcr_")
            .into(),
    ] {
        let response = h
            .http
            .post(format!("{}/mcp", h.server.url))
            .bearer_auth(invalid)
            .send()
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }
    let mut changed = h.config.clone();
    changed.upstream_url.set_path("/different");
    let changed = Server::start(router(changed).unwrap()).await;
    let response = h
        .http
        .post(format!("{}/mcp", changed.url))
        .bearer_auth(access)
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    assert_eq!(std::fs::read(&h.config.token_key_file).unwrap().len(), 32);
}

#[tokio::test]
async fn upstream_statuses_and_discovery_challenges_are_preserved() {
    let h = Harness::new(false).await;
    let access = h.access_token("none").await;
    let response = h
        .http
        .post(format!("{}/mcp", h.server.url))
        .bearer_auth(&access)
        .header("x-test-response", "notification")
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::ACCEPTED);
    let response = h
        .http
        .post(format!("{}/mcp", h.server.url))
        .bearer_auth(&access)
        .header("x-test-response", "unauthorized")
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    let challenge = response.headers()["www-authenticate"].to_str().unwrap();
    assert!(challenge.contains("proxy.example"));
    assert!(!challenge.contains("realm=\"upstream\""));
    assert_eq!(response.text().await.unwrap(), "upstream rejected key");
    let response = h
        .http
        .post(format!("{}/mcp", h.server.url))
        .bearer_auth(&access)
        .header("x-test-response", "timeout")
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::GATEWAY_TIMEOUT);
    let response = h
        .http
        .post(format!("{}/mcp", h.server.url))
        .bearer_auth(&access)
        .header("x-test-response", "redirect")
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::TEMPORARY_REDIRECT);
    let response = h
        .http
        .post(format!("{}/mcp", h.server.url))
        .bearer_auth(&access)
        .header("origin", "https://evil.example")
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::FORBIDDEN);
    let response = h
        .http
        .post(format!("{}/mcp?access_token=secret", h.server.url))
        .bearer_auth(&access)
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    let response = h
        .http
        .put(format!("{}/mcp", h.server.url))
        .bearer_auth(&access)
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::METHOD_NOT_ALLOWED);
    assert_eq!(response.headers()["allow"], "GET, POST, DELETE");
}

#[test]
fn configuration_rejects_unsafe_urls_and_unknown_options() {
    for public in [
        "http://public.example",
        "https://user:password@proxy.example",
        "https://proxy.example/prefix?query=1",
        "https://proxy.example/prefix#fragment",
        "https://proxy.example/a//b",
        "https://proxy.example/{route}",
        "https://proxy.example/space%20here",
    ] {
        let config: Config = toml::from_str(&format!(
            "public_url = '{public}'\nupstream_url = 'https://upstream.example/mcp'\n"
        ))
        .unwrap();
        assert!(config.validate().is_err());
    }
    assert!(toml::from_str::<Config>("public_url = 'http://localhost:8080'\nupstream_url = 'https://upstream.example/mcp'\nupsteam_url = 'typo'\n").is_err());
    let config: Config = toml::from_str(
        "public_url = 'http://127.0.0.1:8080'\nupstream_url = 'https://upstream.example/mcp'\n",
    )
    .unwrap();
    assert!(config.validate().is_ok());
    for public in [
        "https://proxy.example/services/one",
        "https://proxy.example/services/one/",
    ] {
        let config: Config = toml::from_str(&format!(
            "public_url = '{public}'\nupstream_url = 'https://upstream.example/mcp'\n"
        ))
        .unwrap();
        assert!(config.validate().is_ok());
        assert_eq!(config.issuer(), "https://proxy.example/services/one");
        assert_eq!(config.origins(), ["https://proxy.example"]);
    }
}

#[tokio::test]
async fn two_path_instances_share_one_origin_with_isolated_discovery_and_tokens() {
    let mut a = Harness::new_at_prefix(false, "/services/alpha/").await;
    let mut b = Harness::new_at_prefix(false, "/services/beta").await;
    // A shared key still cannot make tokens or registrations cross instances.
    b.config.token_key_file = a.config.token_key_file.clone();
    let shared = Server::start(
        router(a.config.clone())
            .unwrap()
            .merge(router(b.config.clone()).unwrap()),
    )
    .await;
    a.server.url = format!("{}{}", shared.url, a.config.prefix());
    b.server.url = format!("{}{}", shared.url, b.config.prefix());
    for h in [&a, &b] {
        let response = h
            .http
            .get(format!("{}/mcp", h.server.url))
            .send()
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
        assert_eq!(
            response.headers()["www-authenticate"],
            format!(
                "Bearer resource_metadata=\"{}\"",
                h.config.resource_metadata_url()
            )
        );
        for path in [
            h.config.resource_metadata_path(),
            h.config
                .endpoint_path("/.well-known/oauth-protected-resource"),
            h.config
                .endpoint_path("/.well-known/oauth-protected-resource/mcp"),
        ] {
            let response = h
                .http
                .get(format!("{}{path}", shared.url))
                .send()
                .await
                .unwrap();
            assert_eq!(response.status(), StatusCode::OK);
            let metadata: Value = response.json().await.unwrap();
            assert_eq!(metadata["resource"], h.config.resource());
            assert_eq!(
                metadata["authorization_servers"],
                json!([h.config.issuer()])
            );
        }
        for path in [
            h.config.server_metadata_path(),
            h.config
                .endpoint_path("/.well-known/oauth-authorization-server"),
            h.config.endpoint_path("/.well-known/openid-configuration"),
            format!("/.well-known/openid-configuration{}", h.config.prefix()),
        ] {
            let metadata: Value = h
                .http
                .get(format!("{}{path}", shared.url))
                .send()
                .await
                .unwrap()
                .json()
                .await
                .unwrap();
            assert_eq!(metadata["issuer"], h.config.issuer());
            assert_eq!(
                metadata["authorization_endpoint"],
                format!("{}/oauth/authorize", h.config.issuer())
            );
            assert_eq!(
                metadata["token_endpoint"],
                format!("{}/oauth/token", h.config.issuer())
            );
            assert_eq!(
                metadata["registration_endpoint"],
                format!("{}/oauth/register", h.config.issuer())
            );
        }
        let health = h
            .http
            .get(format!("{}/healthz", h.server.url))
            .send()
            .await
            .unwrap();
        assert_eq!(health.status(), StatusCode::OK);
        let access = h.access_token("client_secret_post").await;
        let response = h
            .http
            .post(format!("{}/mcp", h.server.url))
            .bearer_auth(&access)
            .header("origin", h.config.origin())
            .send()
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(
            response.headers()["access-control-allow-origin"],
            h.config.origin()
        );
        let other = if std::ptr::eq(h, &a) { &b } else { &a };
        let response = h
            .http
            .post(format!("{}/mcp", other.server.url))
            .bearer_auth(&access)
            .send()
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }
    let registration = a.register("none").await;
    let response = b
        .http
        .get(format!("{}/oauth/authorize", b.server.url))
        .query(&[
            ("response_type", "code"),
            ("client_id", registration["client_id"].as_str().unwrap()),
            ("redirect_uri", CALLBACK),
            (
                "code_challenge",
                URL_SAFE_NO_PAD
                    .encode(Sha256::digest(VERIFIER.as_bytes()))
                    .as_str(),
            ),
            ("code_challenge_method", "S256"),
        ])
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    assert_eq!(
        response.json::<Value>().await.unwrap()["error"],
        "invalid_client"
    );
    for path in [
        "/mcp",
        "/oauth/authorize",
        "/healthz",
        "/.well-known/oauth-authorization-server",
        "/.well-known/oauth-protected-resource/mcp",
    ] {
        assert_eq!(
            a.http
                .get(format!("{}{path}", shared.url))
                .send()
                .await
                .unwrap()
                .status(),
            StatusCode::NOT_FOUND
        );
    }
    assert_eq!(a.captures.lock().unwrap().len(), 1);
    assert_eq!(b.captures.lock().unwrap().len(), 1);
}

#[tokio::test]
async fn abandoned_authorization_forms_do_not_starve_other_clients() {
    let h = Harness::new_at_prefix(false, "/one").await;
    let legitimate = h.register("none").await;
    let id = legitimate["client_id"].as_str().unwrap();
    let (ticket, cookie) = h.authorize(id).await;
    let attacker = h.register("none").await;
    for _ in 0..1024 {
        h.authorize(attacker["client_id"].as_str().unwrap()).await;
    }
    // The form opened before the flood and a fresh form both remain usable.
    let code = h.consent(&ticket, &cookie, Some(KEY)).await;
    h.authorize(id).await;
    let response = h
        .http
        .post(format!("{}/oauth/token", h.server.url))
        .form(&h.token_form(id, &code))
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);

    // Neither another browser cookie nor another sealed purpose is a form ticket.
    for (bad_ticket, bad_cookie) in [
        (ticket.as_str(), "mcp_oauth_other=other"),
        (id.strip_prefix("dcr_").unwrap(), cookie.as_str()),
    ] {
        let response = h
            .http
            .post(format!("{}/oauth/authorize", h.server.url))
            .header("cookie", bad_cookie)
            .header("origin", h.config.origin())
            .form(&[
                ("ticket", bad_ticket),
                ("action", "allow"),
                ("api_token", KEY),
            ])
            .send()
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        assert!(!response.headers().contains_key("location"));
    }
}

#[tokio::test]
async fn stateless_forms_obey_callback_changes_after_restart() {
    let mut h = Harness::new_at_prefix(true, "/one").await;
    let (ticket, cookie) = h.authorize("configured-client").await;
    h.config.oauth.redirect_uris = vec!["https://replacement.example/callback".into()];
    h.server = Server::start(router(h.config.clone()).unwrap()).await;
    h.server.url.push_str(h.config.prefix());
    let response = h
        .http
        .post(format!("{}/oauth/authorize", h.server.url))
        .header("cookie", cookie)
        .header("origin", h.config.origin())
        .form(&[("ticket", ticket.as_str()), ("action", "allow")])
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    assert!(!response.headers().contains_key("location"));
}

#[tokio::test]
async fn stateless_forms_preserve_maximum_escaped_state_and_api_keys() {
    let h = Harness::new(false).await;
    let redirects: Vec<_> = (0..5)
        .map(|i| format!("https://client.example/{i}/{}", "a".repeat(480)))
        .collect();
    let registration: Value = h.http.post(format!("{}/oauth/register", h.server.url))
        .json(&json!({"redirect_uris": redirects, "client_name": "\0".repeat(200), "token_endpoint_auth_method": "none"}))
        .send().await.unwrap().json().await.unwrap();
    let id = registration["client_id"].as_str().unwrap();
    let challenge = URL_SAFE_NO_PAD.encode(Sha256::digest(VERIFIER.as_bytes()));
    let state = "\0".repeat(2048);
    let response = h
        .http
        .get(format!("{}/oauth/authorize", h.server.url))
        .query(&[
            ("response_type", "code"),
            ("client_id", id),
            ("redirect_uri", redirects[0].as_str()),
            ("code_challenge", challenge.as_str()),
            ("code_challenge_method", "S256"),
            ("state", state.as_str()),
        ])
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let cookie = response.headers()["set-cookie"]
        .to_str()
        .unwrap()
        .split(';')
        .next()
        .unwrap()
        .to_owned();
    let html = response.text().await.unwrap();
    let ticket = html
        .split("name=ticket value=\"")
        .nth(1)
        .unwrap()
        .split('"')
        .next()
        .unwrap();
    assert!(ticket.len() > 16_384);
    let key = "&".repeat(4096);
    let response = h
        .http
        .post(format!("{}/oauth/authorize", h.server.url))
        .header("cookie", cookie)
        .header("origin", h.config.origin())
        .form(&[
            ("ticket", ticket),
            ("action", "allow"),
            ("api_token", key.as_str()),
        ])
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::SEE_OTHER);
    let callback = Url::parse(response.headers()["location"].to_str().unwrap()).unwrap();
    let pairs: std::collections::HashMap<_, _> = callback.query_pairs().into_owned().collect();
    assert_eq!(pairs["state"], state);
    let mut form = h.token_form(id, &pairs["code"]);
    form.iter_mut()
        .find(|(name, _)| name == "redirect_uri")
        .unwrap()
        .1 = redirects[0].clone();
    assert_eq!(
        h.http
            .post(format!("{}/oauth/token", h.server.url))
            .form(&form)
            .send()
            .await
            .unwrap()
            .status(),
        StatusCode::OK
    );
}

#[tokio::test]
async fn unexchanged_code_flood_is_limited_and_recovers_promptly() {
    let h = Harness::new_at_prefix(true, "/one").await;
    let started = std::time::Instant::now();
    let mut issued = 1;
    let legitimate = h.register("none").await;
    let id = legitimate["client_id"].as_str().unwrap();
    let (ticket, cookie) = h.authorize(id).await;
    let saved_code = h.consent(&ticket, &cookie, Some(KEY)).await;
    let attacker = h.register("none").await;
    let attacker_id = attacker["client_id"].as_str().unwrap();
    let (mut ticket, mut cookie) = h.authorize(attacker_id).await;
    let mut limited = 0;
    // Original attack: distinct forms. Alternate attack: replay one valid form.
    for fresh_form in [true, false] {
        for _ in 0..1024 {
            if fresh_form {
                (ticket, cookie) = h.authorize(attacker_id).await;
            }
            let response = h
                .http
                .post(format!("{}/oauth/authorize", h.server.url))
                .header("cookie", &cookie)
                .header("origin", h.config.origin())
                .form(&[
                    ("ticket", ticket.as_str()),
                    ("action", "allow"),
                    ("api_token", "syntactically-valid-invalid-key"),
                ])
                .send()
                .await
                .unwrap();
            match response.status() {
                StatusCode::SEE_OTHER => {
                    issued += 1;
                }
                StatusCode::TOO_MANY_REQUESTS => {
                    limited += 1;
                    assert_eq!(response.headers()["retry-after"], "1");
                    assert_eq!(response.headers()["cache-control"], "no-store");
                }
                status => panic!("Unexpected flood response {status}"),
            }
        }
    }
    assert!(limited > 0);
    // Already issued codes are neither evicted nor rate limited at exchange.
    let response = h
        .http
        .post(format!("{}/oauth/token", h.server.url))
        .form(&h.token_form(id, &saved_code))
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let access = response.json::<Value>().await.unwrap()["access_token"]
        .as_str()
        .unwrap()
        .to_owned();
    assert_eq!(
        h.http
            .get(format!("{}/mcp", h.server.url))
            .bearer_auth(access)
            .send()
            .await
            .unwrap()
            .status(),
        StatusCode::OK
    );

    // Newly registered identities cannot reset the issuance budget.
    for _ in 0..16 {
        let sybil = h.register("none").await;
        let (sybil_ticket, sybil_cookie) = h.authorize(sybil["client_id"].as_str().unwrap()).await;
        let response = h
            .http
            .post(format!("{}/oauth/authorize", h.server.url))
            .header("cookie", sybil_cookie)
            .header("origin", h.config.origin())
            .form(&[
                ("ticket", sybil_ticket.as_str()),
                ("action", "allow"),
                ("api_token", KEY),
            ])
            .send()
            .await
            .unwrap();
        match response.status() {
            StatusCode::SEE_OTHER => {
                issued += 1;
            }
            StatusCode::TOO_MANY_REQUESTS => {}
            status => panic!("Unexpected new-client response {status}"),
        }
    }
    // Include elapsed replenishment so this remains valid on slow CI runners.
    assert!(issued <= 32 + (started.elapsed().as_secs_f64() * 2.0).ceil() as usize);
    // Recovery takes one retry interval, rather than waiting for the 120s TTL.
    let (ticket, cookie) = h.authorize("configured-client").await;
    tokio::time::sleep(Duration::from_secs(1)).await;
    let code = h.consent(&ticket, &cookie, None).await;
    let mut form = h.token_form("configured-client", &code);
    form.push(("client_secret".into(), KEY.into()));
    let response = h
        .http
        .post(format!("{}/oauth/token", h.server.url))
        .form(&form)
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
}

async fn raw_response(mut stream: TcpStream) -> String {
    let mut bytes = Vec::new();
    tokio::time::timeout(Duration::from_secs(3), stream.read_to_end(&mut bytes))
        .await
        .expect("socket was retained past its deadline")
        .unwrap();
    String::from_utf8_lossy(&bytes).into_owned()
}

#[tokio::test]
async fn slow_oauth_bodies_expire_for_every_endpoint_and_body_encoding() {
    let h = Harness::new_with_limits(
        false,
        "/services/one",
        Limits {
            oauth_body_timeout_seconds: 1,
            ..Limits::default()
        },
    )
    .await;
    let address = Url::parse(&h.server.url)
        .unwrap()
        .socket_addrs(|| None)
        .unwrap()[0];
    let mut streams = Vec::new();
    for endpoint in ["register", "authorize", "token"] {
        for framing in ["Content-Length: 100", "Transfer-Encoding: chunked"] {
            let mut stream = TcpStream::connect(address).await.unwrap();
            let content_type = if endpoint == "register" {
                "application/json"
            } else {
                "application/x-www-form-urlencoded"
            };
            let partial = if framing.starts_with("Content-Length") {
                "x"
            } else {
                "64\r\nx"
            };
            stream.write_all(format!("POST /services/one/oauth/{endpoint} HTTP/1.1\r\nHost: proxy.example\r\nContent-Type: {content_type}\r\n{framing}\r\nConnection: close\r\n\r\n{partial}").as_bytes()).await.unwrap();
            streams.push(stream);
        }
    }
    for stream in streams {
        assert!(raw_response(stream).await.starts_with("HTTP/1.1 408"));
    }
    assert_eq!(
        h.http
            .get(format!("{}/healthz", h.server.url))
            .send()
            .await
            .unwrap()
            .status(),
        StatusCode::OK
    );
    h.access_token("none").await;
}

#[tokio::test]
async fn socket_cap_rejects_excess_connections_and_slow_headers_expire() {
    let limits = Limits {
        max_connections: 2,
        header_timeout_seconds: 1,
        ..Limits::default()
    };
    let h = Harness::new_with_limits(false, "", limits).await;
    let address = Url::parse(&h.server.url)
        .unwrap()
        .socket_addrs(|| None)
        .unwrap()[0];
    let idle = TcpStream::connect(address).await.unwrap();
    let mut partial = TcpStream::connect(address).await.unwrap();
    partial
        .write_all(b"GET /healthz HTTP/1.1\r\nHost:")
        .await
        .unwrap();
    tokio::time::sleep(Duration::from_millis(50)).await;
    let excess = TcpStream::connect(address).await.unwrap();
    assert!(raw_response(excess).await.is_empty());
    // Header deadlines may close the socket silently instead of sending 408.
    let idle_response = raw_response(idle).await;
    assert!(idle_response.is_empty() || idle_response.starts_with("HTTP/1.1 408"));
    let partial_response = raw_response(partial).await;
    assert!(partial_response.is_empty() || partial_response.starts_with("HTTP/1.1 408"));
    assert_eq!(
        h.http
            .get(format!("{}/healthz", h.server.url))
            .send()
            .await
            .unwrap()
            .status(),
        StatusCode::OK
    );
}

#[tokio::test]
async fn stream_permits_are_held_until_eof_or_disconnect() {
    let h = Harness::new_with_limits(
        false,
        "",
        Limits {
            max_requests: 1,
            header_timeout_seconds: 1,
            oauth_body_timeout_seconds: 1,
            ..Limits::default()
        },
    )
    .await;
    let access = h.access_token("none").await;
    for disconnect in [false, true] {
        let mut stream = h
            .http
            .get(format!("{}/mcp", h.server.url))
            .bearer_auth(&access)
            .header("x-test-response", "sse")
            .send()
            .await
            .unwrap();
        assert!(stream.chunk().await.unwrap().is_some());
        let overloaded = h
            .http
            .get(format!("{}/mcp", h.server.url))
            .bearer_auth(&access)
            .send()
            .await
            .unwrap();
        assert_eq!(overloaded.status(), StatusCode::SERVICE_UNAVAILABLE);
        assert_eq!(overloaded.headers()["retry-after"], "1");
        assert_eq!(
            h.captures.lock().unwrap().len(),
            if disconnect { 3 } else { 1 }
        );
        if !disconnect {
            // The stream remains alive past both inbound deadlines.
            assert!(stream.chunk().await.unwrap().is_some());
            assert!(stream.chunk().await.unwrap().is_none());
        }
        drop(stream);
        tokio::time::sleep(Duration::from_millis(50)).await;
        assert_eq!(
            h.http
                .get(format!("{}/mcp", h.server.url))
                .bearer_auth(&access)
                .send()
                .await
                .unwrap()
                .status(),
            StatusCode::OK
        );
    }
}
