use std::{sync::Arc, time::Duration};

use axum::{
    Json,
    body::Body,
    extract::{Request, State},
    http::{HeaderMap, Method, StatusCode, header},
    response::{IntoResponse, Response},
};
use serde_json::json;

use crate::{App, oauth::valid_api_key};

fn unauthorized(app: &App, invalid: bool) -> Response {
    let mut response = (
        StatusCode::UNAUTHORIZED,
        Json(json!({"error": "unauthorized"})),
    )
        .into_response();
    challenge(app, response.headers_mut(), invalid);
    response
}

fn challenge(app: &App, headers: &mut HeaderMap, invalid: bool) {
    let value = format!(
        "Bearer resource_metadata=\"{}\"{}",
        app.config.resource_metadata_url(),
        if invalid {
            ", error=\"invalid_token\""
        } else {
            ""
        }
    );
    headers.insert(header::WWW_AUTHENTICATE, value.parse().unwrap());
    headers.insert(header::CACHE_CONTROL, "no-store".parse().unwrap());
}

/// Remove hop-by-hop headers, including arbitrary names nominated by Connection.
fn end_to_end(headers: &HeaderMap) -> HeaderMap {
    let mut clean = headers.clone();
    for value in headers
        .get_all(header::CONNECTION)
        .iter()
        .filter_map(|v| v.to_str().ok())
    {
        for name in value.split(',') {
            if let Ok(name) = name.trim().parse::<axum::http::HeaderName>() {
                clean.remove(name);
            }
        }
    }
    for name in [
        "connection",
        "keep-alive",
        "proxy-authenticate",
        "proxy-authorization",
        "te",
        "trailer",
        "transfer-encoding",
        "upgrade",
    ] {
        clean.remove(name);
    }
    clean
}

pub(crate) async fn forward(State(app): State<Arc<App>>, request: Request) -> Response {
    if !matches!(
        *request.method(),
        Method::GET | Method::POST | Method::DELETE
    ) {
        let mut response = StatusCode::METHOD_NOT_ALLOWED.into_response();
        response
            .headers_mut()
            .insert(header::ALLOW, "GET, POST, DELETE".parse().unwrap());
        return response;
    }
    if request
        .headers()
        .get_all(header::ORIGIN)
        .iter()
        .any(|origin| {
            !origin
                .to_str()
                .is_ok_and(|origin| app.config.origins().iter().any(|allowed| origin == allowed))
        })
    {
        return (StatusCode::FORBIDDEN, "Origin is not allowed").into_response();
    }
    if request
        .headers()
        .get_all(header::AUTHORIZATION)
        .iter()
        .count()
        != 1
    {
        return unauthorized(&app, request.headers().contains_key(header::AUTHORIZATION));
    }
    let Some(key) = request
        .headers()
        .get(header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .and_then(|value| value.split_once(' '))
        .filter(|(scheme, _)| scheme.eq_ignore_ascii_case("Bearer"))
        .and_then(|(_, token)| app.sealer.open::<String>("access", token))
        .filter(|key| valid_api_key(key))
    else {
        return unauthorized(&app, true);
    };
    let (parts, body) = request.into_parts();
    let mut target = app.config.upstream_url.clone();
    // Keep the configured query and append the client's transport query verbatim.
    if let Some(query) = parts.uri.query() {
        if url::form_urlencoded::parse(query.as_bytes()).any(|(name, _)| name == "access_token") {
            return (
                StatusCode::BAD_REQUEST,
                "Use the Authorization header for access tokens",
            )
                .into_response();
        }
        target.set_query(Some(&match target.query() {
            Some(existing) => format!("{existing}&{query}"),
            None => query.to_owned(),
        }));
    }
    let mut headers = end_to_end(&parts.headers);
    for name in [
        "host",
        "authorization",
        "cookie",
        "referer",
        "forwarded",
        "x-forwarded-for",
        "x-forwarded-host",
        "x-forwarded-proto",
        "x-real-ip",
    ] {
        headers.remove(name);
    }
    // Origin is a transport security header, not MCP payload. The upstream sees
    // its own origin after the proxy validates the client's origin above.
    if headers.contains_key(header::ORIGIN) {
        headers.insert(
            header::ORIGIN,
            target.origin().ascii_serialization().parse().unwrap(),
        );
    }
    let outgoing = app
        .http
        .request(parts.method, target)
        .headers(headers)
        .bearer_auth(key)
        .body(reqwest::Body::wrap_stream(body.into_data_stream()));
    let upstream = match tokio::time::timeout(
        Duration::from_secs(app.config.upstream_header_timeout_seconds),
        outgoing.send(),
    )
    .await
    {
        Ok(Ok(response)) => response,
        Ok(Err(_)) => {
            return (StatusCode::BAD_GATEWAY, "Upstream connection failed").into_response();
        }
        Err(_) => {
            return (StatusCode::GATEWAY_TIMEOUT, "Upstream response timed out").into_response();
        }
    };
    let status = upstream.status();
    // Redirects are deliberately not followed: they could disclose the API key
    // to another host. Upstream login challenges point at our OAuth surface.
    let mut headers = end_to_end(upstream.headers());
    headers.remove(header::SET_COOKIE);
    if status == StatusCode::UNAUTHORIZED {
        challenge(&app, &mut headers, true);
    }
    let mut response = Response::new(Body::from_stream(upstream.bytes_stream()));
    *response.status_mut() = status;
    *response.headers_mut() = headers;
    response
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn strips_all_connection_nominated_headers() {
        let mut headers = HeaderMap::new();
        headers.append(header::CONNECTION, "keep-alive, x-private".parse().unwrap());
        headers.append(header::CONNECTION, "x-second".parse().unwrap());
        headers.insert("x-private", "secret".parse().unwrap());
        headers.insert("x-second", "secret".parse().unwrap());
        headers.insert("mcp-session-id", "session".parse().unwrap());
        let clean = end_to_end(&headers);
        assert!(!clean.contains_key("connection"));
        assert!(!clean.contains_key("x-private"));
        assert!(!clean.contains_key("x-second"));
        assert_eq!(clean["mcp-session-id"], "session");
    }
}
