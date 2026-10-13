#!/usr/bin/env bash
# An offline Surfpool process, real signatures and SBF execution, no wallet config.
set -euo pipefail
cd "$(dirname "$0")/.."
export CARGO_INCREMENTAL=0
export CARGO_NET_OFFLINE=true
export CARGO_TARGET_DIR="${CARGO_TARGET_DIR:-$PWD/target/credit-provider-e2e}"
export PAYMENT_CHANNELS_V2_SO="${PAYMENT_CHANNELS_V2_SO:-$PWD/target/deploy-v2/payment_channels.so}"
export CREDIT_PROVIDER_SO="${CREDIT_PROVIDER_SO:-$PWD/target/deploy/credit_provider.so}"
# SBPF v3 deployment requires a recent Agave CLI; do not alter the global install.
export SOLANA_CLI="${SOLANA_CLI:-solana}"
for cmd in surfpool "$SOLANA_CLI" curl cargo; do command -v "$cmd" >/dev/null; done
test -f "$PAYMENT_CHANNELS_V2_SO"
test -f "$CREDIT_PROVIDER_SO"
mkdir -p target
run_dir="$(mktemp -d "$PWD/target/credit-provider-surfpool.XXXXXX")"
export CREDIT_E2E_RUN_DIR="$run_dir"
# Use dedicated loopback ports; never accept a remote RPC override.
port="${CREDIT_E2E_PORT:-18899}"
export CREDIT_E2E_RPC="http://127.0.0.1:$port"
pid=""
cleanup() {
    if [[ -n "$pid" ]]; then kill "$pid" 2>/dev/null || true; wait "$pid" 2>/dev/null || true; fi
    # Retain diagnostics, never ephemeral private keys.
    rm -f "$run_dir/issuer.json" "$run_dir/provider.json"
}
trap cleanup EXIT INT TERM
if curl --noproxy '*' --silent --connect-timeout 1 "$CREDIT_E2E_RPC" >/dev/null 2>&1; then
    echo "Refusing occupied RPC port $port" >&2
    exit 1
fi
surfpool --version
surfpool start --offline --no-deploy --no-tui --no-studio --host 127.0.0.1 \
    --airdrop-amount 0 --port "$port" --ws-port "$((port + 1))" \
    --log-path "$run_dir/logs" >"$run_dir/surfpool.log" 2>&1 &
pid=$!
ready=0
for _ in {1..100}; do
    if curl --noproxy '*' --silent --fail --max-time 1 \
        -H 'Content-Type: application/json' \
        -d '{"jsonrpc":"2.0","id":1,"method":"getHealth"}' \
        "$CREDIT_E2E_RPC" | grep -q '"ok"'; then ready=1; break; fi
    kill -0 "$pid" 2>/dev/null || { cat "$run_dir/surfpool.log"; exit 1; }
    sleep .1
done
[[ "$ready" == 1 ]] || { cat "$run_dir/surfpool.log"; exit 1; }
echo "Surfpool diagnostics: $run_dir"
cargo run --offline --manifest-path scripts/credit-provider-e2e/Cargo.toml
