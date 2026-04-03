use anyhow::Result;
use aws_lc_rs::rand;
use aws_lc_rs::signature::{ECDSA_P256_SHA256_FIXED_SIGNING, EcdsaKeyPair, KeyPair};
use axum::Router;
use axum::http::uri::PathAndQuery;
use axum::serve::Serve;
use axum::{body::Body, extract::State, http::Request, response::IntoResponse, response::Response};
use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::net::TcpListener;
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

#[derive(Clone)]
struct ProxyState {
    key_pair: Arc<EcdsaKeyPair>,
    client: Arc<reqwest::Client>,
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::registry()
        .with(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("debug")),
        )
        .with(tracing_subscriber::fmt::layer())
        .init();

    let key_pair = Arc::new(create_key_pair()?);
    let client = Arc::new(reqwest::Client::new());

    let jwks_server = create_jwks_sever(key_pair.clone()).await?;
    let proxy_server = create_proxy_server(key_pair.clone(), client.clone()).await?;

    // TODO: graceful shutdown
    // Combine all servers.
    tokio::try_join!(jwks_server, proxy_server)?;
    Ok(())
}

async fn create_jwks_sever(
    key_pair: Arc<EcdsaKeyPair>,
) -> Result<Serve<TcpListener, Router, Router>> {
    let app = axum::Router::new()
        .route("/jwks.json", axum::routing::get(jwks_handler))
        .with_state(key_pair)
        .layer(tower_http::trace::TraceLayer::new_for_http());

    let addr = SocketAddr::from(([127, 0, 0, 1], 8081));
    let listener = TcpListener::bind(addr).await?;
    Ok(axum::serve(listener, app))
}

async fn jwks_handler(
    State(key_pair): State<Arc<EcdsaKeyPair>>,
) -> std::result::Result<impl IntoResponse, (axum::http::StatusCode, String)> {
    let jwks = dump_jwks(&key_pair, "test-key-id").map_err(|err| {
        (
            axum::http::StatusCode::INTERNAL_SERVER_ERROR,
            err.to_string(),
        )
    })?;

    Ok(axum::Json(jwks))
}

async fn create_proxy_server(
    key_pair: Arc<EcdsaKeyPair>,
    client: Arc<reqwest::Client>,
) -> Result<Serve<TcpListener, Router, Router>> {
    let app = axum::Router::new()
        .fallback(proxy_request_handler)
        .with_state(ProxyState { key_pair, client })
        .layer(tower_http::trace::TraceLayer::new_for_http());

    // TODO listener per user/port
    let addr = SocketAddr::from(([127, 0, 0, 1], 8080));
    let listener = TcpListener::bind(addr).await?;
    Ok(axum::serve(listener, app))
}

async fn proxy_request_handler(
    State(state): State<ProxyState>,
    req: Request<Body>,
) -> std::result::Result<impl IntoResponse, (axum::http::StatusCode, String)> {
    proxy_request(&state, req)
        .await
        .map_err(|err| (axum::http::StatusCode::BAD_GATEWAY, err.to_string()))
}

async fn proxy_request(state: &ProxyState, req: Request<Body>) -> Result<Response> {
    let method = req.method().clone();
    let path_and_query = req.uri().path_and_query();
    let query_string = path_and_query
        .map(PathAndQuery::query)
        .flatten()
        .map(str::to_string);
    // TODO: from cli flag
    let url = format!(
        "http://localhost:8000{}",
        path_and_query.map(PathAndQuery::as_str).unwrap_or("/")
    );

    // Forward request body and headers.
    let (parts, body) = req.into_parts();
    let body = axum::body::to_bytes(body, usize::MAX).await?;
    let mut request = state.client.request(method, url).body(body);
    for (name, value) in &parts.headers {
        request = request.header(name, value);
    }

    // Add the IAP JWT header.
    request = request.header(
        "x-goog-iap-jwt-assertion",
        // TODO const for the keyid
        create_jwt(
            &state.key_pair,
            "test-key-id",
            &claims_for_request(
                // TODO: from server state
                "user123@example.com",
                &query_string,
            ),
        )?,
    );

    let response = request.send().await?;

    let status = response.status();
    let resp_headers = response.headers().clone();
    let resp_bytes = response.bytes().await?;

    // Proxy response back.
    let mut headers = axum::http::HeaderMap::new();
    for (name, value) in &resp_headers {
        headers.insert(name, value.clone());
    }

    let mut response = axum::response::Response::builder()
        .status(status)
        .body(axum::body::Body::from(resp_bytes))?;
    *response.headers_mut() = headers;
    Ok(response)
}

fn claims_for_request(user: &str, query: &Option<String>) -> serde_json::Value {
    // TODO
    serde_json::json!({
        "sub": user,
        // TODO: from cli
        "aud": "https://example.com",
        "exp": 1785229363,
        "iat": 1775228363,
        "iss": "https://cloud.google.com/iap",
    })
}

fn create_key_pair() -> Result<EcdsaKeyPair> {
    let rng = rand::SystemRandom::new();
    let pkc8_bytes = EcdsaKeyPair::generate_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, &rng)?;
    Ok(EcdsaKeyPair::from_pkcs8(
        &ECDSA_P256_SHA256_FIXED_SIGNING,
        pkc8_bytes.as_ref(),
    )?)
}

fn dump_jwks(key_pair: &EcdsaKeyPair, kid: &str) -> Result<serde_json::Value> {
    let pub_key_bytes = key_pair.public_key().as_ref();
    let x_bytes = &pub_key_bytes[1..33];
    let y_bytes = &pub_key_bytes[33..65];
    let x_b64 = URL_SAFE_NO_PAD.encode(x_bytes);
    let y_b64 = URL_SAFE_NO_PAD.encode(y_bytes);

    Ok(serde_json::json!({
        "keys": [
            {
                "kty": "EC",
                "alg": "ES256",
                "use": "sig",
                "kid": kid,
                "crv": "P-256",
                "x": x_b64,
                "y": y_b64,
            }
        ]
    }))
}

fn create_jwt(key_pair: &EcdsaKeyPair, kid: &str, claims: &serde_json::Value) -> Result<String> {
    let header = serde_json::json!({
        "alg": "ES256",
        "kid": kid,
    });

    let header_b64 = URL_SAFE_NO_PAD.encode(serde_json::to_string(&header)?);
    let payload_b64 = URL_SAFE_NO_PAD.encode(serde_json::to_string(claims)?);
    let signing_input = format!("{}.{}", header_b64, payload_b64);

    let rng = rand::SystemRandom::new();
    let signature = key_pair.sign(&rng, signing_input.as_bytes())?;
    let signature_b64 = URL_SAFE_NO_PAD.encode(signature.as_ref());

    Ok(format!("{}.{}.{}", header_b64, payload_b64, signature_b64))
}
