use aws_lc_rs::rand;
use aws_lc_rs::signature::{EcdsaKeyPair, ECDSA_P256_SHA256_FIXED_SIGNING, KeyPair};
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;

#[tokio::main]
async fn main() {
    println!("Hello, world!");

    let rng = rand::SystemRandom::new();
    let pkc8_bytes = EcdsaKeyPair::generate_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, &rng)
        .expect("Failed to generate key pair");
    let key_pair = EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, pkc8_bytes.as_ref())
        .expect("Failed to parse key pair");

    let pub_key_bytes = key_pair.public_key().as_ref();
    let x_bytes = &pub_key_bytes[1..33];
    let y_bytes = &pub_key_bytes[33..65];
    let x_b64 = URL_SAFE_NO_PAD.encode(x_bytes);
    let y_b64 = URL_SAFE_NO_PAD.encode(y_bytes);

    let kid = "dummy-key-id";
    let jwks = serde_json::json!({
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
    });
    println!("{}", serde_json::to_string_pretty(&jwks).unwrap());

    let header = serde_json::json!({
        "alg": "ES256",
        "kid": kid,
    });
    let payload = serde_json::json!({
        "sub": "user123",
        "aud": "https://example.com",
    });

    let header_b64 = URL_SAFE_NO_PAD.encode(serde_json::to_string(&header).unwrap());
    let payload_b64 = URL_SAFE_NO_PAD.encode(serde_json::to_string(&payload).unwrap());
    let signing_input = format!("{}.{}", header_b64, payload_b64);

    let signature = key_pair.sign(&rng, signing_input.as_bytes()).expect("Failed to sign");
    let signature_b64 = URL_SAFE_NO_PAD.encode(signature.as_ref());

    println!("{}.{}.{}", header_b64, payload_b64, signature_b64);
}
