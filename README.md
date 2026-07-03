# iapping

Proxy to test services depending on GCP IAP [authentication via JWT headers][gcp-docs-jwt-auth] locally, allowing you to impersonate multiple different users.

## What and why

It's convenient to use GCP Identity-Aware Proxy (IAP) to both restrict access to a service and to expose the end users identity without having to deal with authentication yourself. You only need to verify the JWT header and extract the email of authenticated user from the claims.

However during local development and testing you now need a way to generate those JWTs and potentially to impersonate multiple different users. This tool allows you to do just that without having to implement another authentication method in your service.

## Installation

Via cargo:

```bash
cargo install --locked iapping
```

## How to use

Your service must have a way to configure the JWKS URL. In production this should be set to `https://www.gstatic.com/iap/verify/public_key-jwk` (see ["Verifying the JWT header"][gcp-docs-jwt-verify]).

First, start the `iapping` proxy:

```bash
iapping \
  --target-url http://localhost:8000 \
  --jwks-address 127.0.0.1:9999 \
  --audience /projects/PROJECT_NUMBER/global/backendServices/SERVICE_ID \
  --subjects 127.0.0.1:9001,user1@example.com \
  --subjects 127.0.0.1:9002,user2@example.com \
  --subjects 127.0.0.1:9003,user3@example.com,optional_sample_access_level
```

Then you can start your service like this:

```bash
my-service \
  --listen-address 127.0.0.1:8000 \
  --jwks-url http://localhost:9999/jwks.json
```

Requests to `localhost:9001` will be forwarded to `localhost:8000` with a valid JWT header for `user1@example.com`. Similarly for the other ports and users.

### Docker Compose

It might be more convenient to wrap the proxy and your service together in a Docker Compose file. See the [demo](demo/compose.yaml) for an example. Pre-build Docker image available at `ghcr.io/lacop/iapping`.

### Testing JWT validation logic

This tool also supports the same [JWT test modes][gcp-docs-jwt-testing] as GCP IAP. You can use this to make sure your service behaves as expected when it gets an invalid JWT (most likely it should return 401 error since this should never come from legitimate IAP request).

### Note on ephemeral keys

A new random signing key is generated when `iapping` starts. If your service caches the JWKS and you restart the proxy, you will also need to restart your service, otherwise all subsequent requests will fail with invalid signature.

## Security

This tool is meant for local development and testing. It is not robust against malicious use.

The code in `demo/server.py` is only for showcasing functionality and integration testing. It is not suitable as a production-ready robust JWT validation implementation.

## License

Licensed under MIT license.

## Name

`IAP + ProxyING = iapping`, pronounced like *yapping*

[gcp-docs-jwt-auth]: https://docs.cloud.google.com/iap/docs/signed-headers-howto#securing_iap_headers

[gcp-docs-jwt-verify]: https://docs.cloud.google.com/iap/docs/signed-headers-howto#verifying_the_jwt_header

[gcp-docs-jwt-testing]: https://docs.cloud.google.com/iap/docs/query-parameters-and-headers-howto#testing_jwt_verification
