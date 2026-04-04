# Demo application and end-to-end test

This has a Python webserver that implements IAP JWT auth middleware. Don't use it in production without auditing it yourself.

It has a simple unauthenticated `/health` endpoint and an authenticated `/auth` endpoint that returns the email of the authenticated user, or an error if the JWT is not valid.

The Docker compose file integrates the demo server and *iapping* for end-to-end testing. You can run it with:

```
$ docker compose up --build

# The demo server runs on port 8000
$ curl 127.0.0.1:8000/health
ok

# Without header we get an error
$ curl 127.0.0.1:8000/auth
Unauthorized: Missing JWT header

# The iapping proxy serves JWKS on port 9999
$ curl 127.0.0.1:9999/jwks.json
{"keys":[{"alg":"ES256","crv":"P-256","kid":"test-key-id", ... }]}

# We can use the iapping proxy to forward requests as different users.
# The demo has three users on three different ports.
$ curl 127.0.0.1:9001/auth
ok: user1@example.com
$ curl 127.0.0.1:9002/auth
ok: user2@example.com
$ curl 127.0.0.1:9003/auth
ok: user3@example.com

# IAP test modes are also supported to check the validation logic:
$ curl 127.0.0.1:9001/auth\?gcp-iap-mode=SECURE_TOKEN_TEST\&iap-secure-token-test-type=PAST_EXPIRATION
Unauthorized: Invalid JWT: Signature has expired
```
