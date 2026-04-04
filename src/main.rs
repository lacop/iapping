use std::{net::SocketAddr, sync::Arc};

use anyhow::Result;
use aws_lc_rs::{
    rand,
    signature::{ECDSA_P256_SHA256_FIXED_SIGNING, EcdsaKeyPair, KeyPair},
};
use axum::{
    Router,
    body::Body,
    extract::State,
    http::{Request, uri::PathAndQuery},
    response::{IntoResponse, Response},
    serve::Serve,
};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use clap::Parser;
use tokio::net::TcpListener;
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

const TEST_KEY_ID: &str = "test-key-id";

#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Args {
    /// The URL of the backend to proxy to, eg. http://localhost:8000
    #[arg(long)]
    target_url: String,

    /// Audience presented in the IAP JWT.
    /// Must match the audience expected by the backend.
    #[arg(long)]
    audience: String,

    /// Address to bind the JWKS server to.
    #[arg(long, default_value = "127.0.0.1:8081")]
    jwks_address: SocketAddr,

    /// Mapping of address to subject (email) claim, separated by commas.
    /// Can be repeated.
    #[arg(long, value_parser = parse_add_subject, required = true, value_name = "ADDRESS,SUBJECT")]
    subjects: Vec<(SocketAddr, String)>,
}

fn parse_add_subject(s: &str) -> Result<(SocketAddr, String), String> {
    let (addr_str, sub) = s
        .split_once(',')
        .ok_or_else(|| format!("expected `addr,sub`, got `{s}`"))?;
    let addr = addr_str.parse::<SocketAddr>().map_err(|e| e.to_string())?;
    Ok((addr, sub.to_string()))
}

#[derive(Clone)]
struct ProxyState {
    args: Arc<Args>,
    client: Arc<reqwest::Client>,
    key_pair: Arc<EcdsaKeyPair>,
    sub: String,
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

    let args = Arc::new(Args::parse());

    let client = Arc::new(
        reqwest::ClientBuilder::new()
            .timeout(std::time::Duration::from_secs(10))
            .build()?,
    );
    let key_pair = Arc::new(create_key_pair()?);

    let mut all_servers = Vec::new();

    let jwks_server = create_jwks_server(args.jwks_address, key_pair.clone()).await?;
    all_servers.push(jwks_server.into_future());

    for (addr, sub) in &args.subjects {
        let proxy_server = create_proxy_server(
            *addr,
            args.clone(),
            client.clone(),
            key_pair.clone(),
            sub.clone(),
        )
        .await?;
        all_servers.push(proxy_server.into_future());
    }

    // Run all servers concurrently.
    futures::future::try_join_all(all_servers).await?;
    Ok(())
}

async fn create_jwks_server(
    addr: SocketAddr,
    key_pair: Arc<EcdsaKeyPair>,
) -> Result<Serve<TcpListener, Router, Router>> {
    tracing::info!("Starting JWKS server. Use http://{}/jwks.json", addr);
    let app = axum::Router::new()
        .route("/jwks.json", axum::routing::get(jwks_handler))
        .with_state(key_pair)
        .layer(tower_http::trace::TraceLayer::new_for_http());
    let listener = TcpListener::bind(addr).await?;
    Ok(axum::serve(listener, app))
}

async fn jwks_handler(
    State(key_pair): State<Arc<EcdsaKeyPair>>,
) -> std::result::Result<impl IntoResponse, (axum::http::StatusCode, String)> {
    let jwks = dump_jwks(&key_pair, TEST_KEY_ID).map_err(|err| {
        (
            axum::http::StatusCode::INTERNAL_SERVER_ERROR,
            err.to_string(),
        )
    })?;

    Ok(axum::Json(jwks))
}

async fn create_proxy_server(
    addr: SocketAddr,
    args: Arc<Args>,
    client: Arc<reqwest::Client>,
    key_pair: Arc<EcdsaKeyPair>,
    sub: String,
) -> Result<Serve<TcpListener, Router, Router>> {
    tracing::info!(
        "Starting proxy server. Use http://{}/ for user {}",
        addr,
        sub
    );

    let app = axum::Router::new()
        .fallback(proxy_request_handler)
        .with_state(ProxyState {
            args,
            client,
            key_pair,
            sub,
        })
        .layer(tower_http::trace::TraceLayer::new_for_http());
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
        .and_then(PathAndQuery::query)
        .map(str::to_string);
    let url = format!(
        "{}{}",
        state.args.target_url,
        path_and_query.map(PathAndQuery::as_str).unwrap_or("/")
    );

    // Forward request body, arbitrary limit of 10MiB.
    let (parts, body) = req.into_parts();
    let body = axum::body::to_bytes(body, 10 * 1024 * 1024).await?;
    let mut request = state.client.request(method, url).body(body);

    // Forward original request headers.
    const IAP_JWT_HEADER: &str = "x-goog-iap-jwt-assertion";
    for (name, value) in &parts.headers {
        if name.as_str().eq_ignore_ascii_case(IAP_JWT_HEADER) {
            // GCP IAM will strip this header if client sends it,
            // match that behavior.
            continue;
        }
        request = request.header(name, value);
    }
    // Add the IAP JWT header.
    request = request.header(
        IAP_JWT_HEADER,
        jwt_for_request(&state.key_pair, &state.sub, &query_string, &state.args)?,
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

fn jwt_for_request(
    key_pair: &EcdsaKeyPair,
    user: &str,
    query: &Option<String>,
    args: &Args,
) -> Result<String> {
    let now_unix = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64;

    // Start with valid claims.
    let mut claims = serde_json::json!({
        // Identity claims.
        // In real IAP the subject will be some stable identifier,
        // we use the same as email for simplicity.
        "sub": user,
        "email": user,
        // Other claims.
        "aud": args.audience,
        "iat": now_unix - 30,
        "exp": now_unix - 30 + 600,
        "iss": "https://cloud.google.com/iap",
        // Real payload also has a "google" claim with access_levels,
        // we skip that here to keep things simple.
        // https://docs.cloud.google.com/iap/docs/signed-headers-howto#verifying_the_jwt_payload
    });

    // Support the same testing mechanism as GCP IAP via query string
    // that will send an invalid JWT.
    // https://docs.cloud.google.com/iap/docs/query-parameters-and-headers-howto#testing_jwt_verification
    if let Some(query) = query {
        let qmap = urlparse::parse_qs(query);
        if get_single_value(&qmap, "gcp-iap-mode") == Some("SECURE_TOKEN_TEST") {
            match get_single_value(&qmap, "iap-secure-token-test-type") {
                Some("NOT_SET") => {
                    // Docs are bit confusing, the mode sounds like the token would not be set
                    // at all (which would be a good test case), but it says "A valid JWT" and
                    // indeed based on testing it seems to send a valid token, so this is likely
                    // "not set" in the sense of missing enum value.
                }
                Some("FUTURE_ISSUE") => {
                    claims["iat"] = serde_json::json!(now_unix + 600);
                }
                Some("PAST_EXPIRATION") => {
                    claims["exp"] = serde_json::json!(now_unix - 600);
                }
                Some("ISSUER") => {
                    claims["iss"] = serde_json::json!("invalid-issuer");
                }
                Some("AUDIENCE") => {
                    claims["aud"] = serde_json::json!("invalid-audience");
                }
                Some("SIGNATURE") => {
                    // Generate a new key pair to sign with.
                    let other_key_pair = create_key_pair()?;
                    return create_jwt(&other_key_pair, TEST_KEY_ID, &claims);
                }
                _ => return Err(anyhow::anyhow!("invalid gcp-iap-mode value")),
            }
        }
    }

    create_jwt(key_pair, TEST_KEY_ID, &claims)
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

fn get_single_value<'a>(
    map: &'a std::collections::HashMap<String, Vec<String>>,
    key: &str,
) -> Option<&'a str> {
    map.get(key).and_then(|values| {
        if values.len() == 1 {
            Some(values[0].as_str())
        } else {
            None
        }
    })
}
