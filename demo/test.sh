#!/usr/bin/env bash

# "Integration test" for the iapping tool using the demo server.
# Assumes the server and proxy were started via `docker compose up --build`
# already.

set -exo pipefail

# Helper that asserts curl status code and response text.
assert_curl() {
  local url=$1
  local expected_status=$2
  local expected_response=$3
  
  response=$(curl -s -w "\n%{http_code}" "$url")
  status=$(echo "$response" | tail -n1)
  body=$(echo "$response" | head -n-1)

  if [ "$status" -ne "$expected_status" ]; then
    echo "For ${url}: Expected status ${expected_status} but got ${status}"
    exit 1
  fi

  if [ "$body" != "$expected_response" ]; then
    echo "For ${url}: Expected response '${expected_response}' but got '${body}'"
    exit 1
  fi
}

# Demo server is up.
assert_curl "http://localhost:8000/health" 200 "ok"
# Rejects without header.
assert_curl "http://localhost:8000/auth" 401 "Unauthorized: Missing JWT header"

# Proxy listens on three ports.
assert_curl "http://localhost:9001/health" 200 "ok"
assert_curl "http://localhost:9002/health" 200 "ok"
assert_curl "http://localhost:9003/health" 200 "ok"
# And proxies responses transparently, including errors.
assert_curl "http://localhost:9001/something" 404 "Not Found"
assert_curl "http://localhost:9002/something" 404 "Not Found"
assert_curl "http://localhost:9003/something" 404 "Not Found"

# Three different identities.
assert_curl "http://localhost:9001/auth" 200 "ok: user1@example.com, access_levels: []"
assert_curl "http://localhost:9002/auth" 200 "ok: user2@example.com, access_levels: ['sample_access_level']"
assert_curl "http://localhost:9003/auth" 200 "ok: user3@example.com, access_levels: ['can_have_two', 'access_levels']"

# Can use IAP test mode to test validation logic.
assert_curl "http://localhost:9001/auth?gcp-iap-mode=SECURE_TOKEN_TEST&iap-secure-token-test-type=NOT_SET" \
    200 "ok: user1@example.com, access_levels: []"
assert_curl "http://localhost:9001/auth?gcp-iap-mode=SECURE_TOKEN_TEST&iap-secure-token-test-type=FUTURE_ISSUE" \
    401 "Unauthorized: Invalid JWT: The token is not yet valid (iat)"
assert_curl "http://localhost:9001/auth?gcp-iap-mode=SECURE_TOKEN_TEST&iap-secure-token-test-type=PAST_EXPIRATION" \
    401 "Unauthorized: Invalid JWT: Signature has expired"
assert_curl "http://localhost:9001/auth?gcp-iap-mode=SECURE_TOKEN_TEST&iap-secure-token-test-type=ISSUER" \
    401 "Unauthorized: Invalid JWT: Invalid issuer"
assert_curl "http://localhost:9001/auth?gcp-iap-mode=SECURE_TOKEN_TEST&iap-secure-token-test-type=AUDIENCE" \
    401 "Unauthorized: Invalid JWT: Audience doesn't match (strict)"
assert_curl "http://localhost:9001/auth?gcp-iap-mode=SECURE_TOKEN_TEST&iap-secure-token-test-type=SIGNATURE" \
    401 "Unauthorized: Invalid JWT: Signature verification failed"
assert_curl "http://localhost:9001/auth?gcp-iap-mode=SECURE_TOKEN_TEST&iap-secure-token-test-type=INVALID_TEST_TYPE" \
    502 "invalid gcp-iap-mode value"

echo "All tests passed!"