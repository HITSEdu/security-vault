#!/usr/bin/env bash

set -euo pipefail

BASE_URL="${BASE_URL:-http://localhost:8000}"
ADMIN_TOKEN="${ADMIN_TOKEN:-admin-token}"
WRITER_TOKEN="${WRITER_TOKEN:-writer-token}"
READER_TOKEN="${READER_TOKEN:-reader-token}"
CHILD_KEYS_JSON="${CHILD_KEYS_JSON:-[\"share-1\",\"share-2\",\"share-3\"]}"
SECRET_NAME="${SECRET_NAME:-db_password}"
SECRET_VALUE="${SECRET_VALUE:-super-secret-password}"

tmp_dir="$(mktemp -d)"
trap 'rm -rf "$tmp_dir"' EXIT

request() {
  local method="$1"
  local path="$2"
  local token="${3:-}"
  local data="${4:-}"
  local body_file="$tmp_dir/body.json"
  local status_file="$tmp_dir/status.txt"

  local curl_args=(
    -sS
    -X "$method"
    -o "$body_file"
    -w "%{http_code}"
  )

  if [[ -n "$token" ]]; then
    curl_args+=(-H "X-API-Key: $token")
  fi

  if [[ -n "$data" ]]; then
    curl_args+=(-H "Content-Type: application/json" -d "$data")
  fi

  curl "${curl_args[@]}" "$BASE_URL$path" > "$status_file"
  RESPONSE_STATUS="$(cat "$status_file")"
  RESPONSE_BODY="$(cat "$body_file")"
}

assert_status() {
  local expected="$1"
  if [[ "$RESPONSE_STATUS" != "$expected" ]]; then
    echo "Expected HTTP $expected but got $RESPONSE_STATUS"
    echo "Response: $RESPONSE_BODY"
    exit 1
  fi
}

assert_json_field() {
  local field="$1"
  local expected="$2"
  python3 - "$field" "$expected" "$RESPONSE_BODY" <<'PY'
import json
import sys

field = sys.argv[1]
expected = sys.argv[2]
payload = json.loads(sys.argv[3])
actual = payload.get(field)
if str(actual) != expected:
    print(f"Expected {field}={expected!r}, got {actual!r}")
    sys.exit(1)
PY
}

extract_json_field() {
  local field="$1"
  python3 - "$field" "$RESPONSE_BODY" <<'PY'
import json
import sys

field = sys.argv[1]
payload = json.loads(sys.argv[2])
value = payload.get(field)
if value is None:
    raise SystemExit(f"Field {field!r} not found in response")
print(value)
PY
}

echo "1. Health"
request "GET" "/health"
assert_status "200"
assert_json_field "status" "ok"

echo "2. Whoami admin/writer/reader"
request "GET" "/v1/whoami" "$ADMIN_TOKEN"
assert_status "200"
assert_json_field "role" "admin"

request "GET" "/v1/whoami" "$WRITER_TOKEN"
assert_status "200"
assert_json_field "role" "writer"

request "GET" "/v1/whoami" "$READER_TOKEN"
assert_status "200"
assert_json_field "role" "reader"

echo "3. Write while sealed must fail"
request "PUT" "/v1/secrets/$SECRET_NAME" "$WRITER_TOKEN" "{\"value\":\"$SECRET_VALUE\"}"
assert_status "400"

echo "4. Unseal"
request "POST" "/v1/unseal" "$ADMIN_TOKEN" "{\"child_keys\":$CHILD_KEYS_JSON}"
assert_status "200"
assert_json_field "status" "unsealed"

echo "5. Writer stores secret"
request "PUT" "/v1/secrets/$SECRET_NAME" "$WRITER_TOKEN" "{\"value\":\"$SECRET_VALUE\"}"
assert_status "200"
assert_json_field "status" "stored"

echo "6. Reader reads secret"
request "GET" "/v1/secrets/$SECRET_NAME" "$READER_TOKEN"
assert_status "200"
assert_json_field "value" "$SECRET_VALUE"

echo "7. Reader lists secrets"
request "GET" "/v1/secrets" "$READER_TOKEN"
assert_status "200"
python3 - "$SECRET_NAME" "$RESPONSE_BODY" <<'PY'
import json
import sys

secret_name = sys.argv[1]
payload = json.loads(sys.argv[2])
if secret_name not in payload.get("secrets", []):
    print(f"Secret {secret_name!r} not found in list")
    sys.exit(1)
PY

echo "8. Writer wraps, reader unwraps"
request "POST" "/v1/secrets/$SECRET_NAME/wrap" "$WRITER_TOKEN" '{"ttl_seconds":60}'
assert_status "200"
TOKEN="$(extract_json_field token)"

request "POST" "/v1/unwrap" "$READER_TOKEN" "{\"token\":\"$TOKEN\"}"
assert_status "200"
assert_json_field "value" "$SECRET_VALUE"

echo "9. RBAC checks"
request "PUT" "/v1/secrets/forbidden" "$READER_TOKEN" '{"value":"123"}'
assert_status "403"

request "GET" "/v1/status" "$WRITER_TOKEN"
assert_status "403"

request "GET" "/v1/status" "$ADMIN_TOKEN"
assert_status "200"

echo "10. Seal and verify reads fail again"
request "POST" "/v1/seal" "$ADMIN_TOKEN"
assert_status "200"
assert_json_field "status" "sealed"

request "GET" "/v1/secrets/$SECRET_NAME" "$READER_TOKEN"
assert_status "400"

echo "All checks passed."
