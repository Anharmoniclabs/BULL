#!/usr/bin/env bash
# Foreground loopback-only test deployment. Never reuse its credentials in production.
set -euo pipefail
umask 077
if [ "$#" -ne 1 ]; then
    printf 'Usage: %s NEW_PRIVATE_TEST_DIRECTORY\n' "$0" >&2
    exit 2
fi
mkdir -m 0700 -- "$1"
TEST_DIR="$(cd -- "$1" && pwd -P)"
openssl rand -out "$TEST_DIR/anchor-test.key" 32
openssl req -x509 -newkey rsa:2048 -nodes -days 1 \
    -subj /CN=localhost -addext subjectAltName=DNS:localhost,IP:127.0.0.1 \
    -keyout "$TEST_DIR/tls-test.key" -out "$TEST_DIR/tls-test.crt"
printf 'TEST ONLY: https://localhost:9443/v1/checkpoints\n' >&2
exec python3 -m bulldog.anchor_service --database "$TEST_DIR/audit.sqlite" \
    --key-file "$TEST_DIR/anchor-test.key" --test-cert "$TEST_DIR/tls-test.crt" \
    --test-tls-key "$TEST_DIR/tls-test.key"
