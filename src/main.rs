use anyhow::Result;
use aws_lc_rs::rand;
use aws_lc_rs::signature::{ECDSA_P256_SHA256_FIXED_SIGNING, EcdsaKeyPair, KeyPair};
use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;

#[tokio::main]
async fn main() -> Result<()> {
    let key_pair = create_key_pair()?;

    let kid = "test-key-id";
    let jwks = dump_jwks(&key_pair, kid)?;
    println!("JWKS:\n{}", serde_json::to_string_pretty(&jwks)?);

    let claims = serde_json::json!({
        "sub": "user123",
        "aud": "https://example.com",
    });
    let token = create_jwt(&key_pair, kid, &claims)?;
    println!("JWT:\n{}", token);

    Ok(())
}

// let header = serde_json::json!({
//     "alg": "ES256",
//     "kid": kid,
// });
// let payload = serde_json::json!({
//     "sub": "user123",
//     "aud": "https://example.com",
// });

// let header_b64 = URL_SAFE_NO_PAD.encode(serde_json::to_string(&header).unwrap());
// let payload_b64 = URL_SAFE_NO_PAD.encode(serde_json::to_string(&payload).unwrap());
// let signing_input = format!("{}.{}", header_b64, payload_b64);

// let signature = key_pair.sign(&rng, signing_input.as_bytes()).expect("Failed to sign");
// let signature_b64 = URL_SAFE_NO_PAD.encode(signature.as_ref());

// println!("{}.{}.{}", header_b64, payload_b64, signature_b64);

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
