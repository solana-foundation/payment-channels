#!/usr/bin/env bash
# Local binary reload regression, NOT a signed loader upgrade.
set -euo pipefail
cd "$(dirname "$0")/../.."
export CARGO_INCREMENTAL=0
export CARGO_NET_OFFLINE=true
baseline=25df9636698c320a0716ba224cbc8724acf63edf
source_dir="$PWD/target/v1-upgrade-baseline"
mkdir -p "$source_dir"
git archive "$baseline" | tar -x -C "$source_dir"
# Always build the actual old source and current source independently. In particular,
# never unify current no-entrypoint host dependencies with an SBF build.
build_root="${UPGRADE_BUILD_ROOT:-$PWD/target/v1-upgrade-build}"
export UPGRADE_OLD_SO="$PWD/target/v1-upgrade-old/payment_channels.so"
export UPGRADE_NEW_SO="$PWD/target/v1-upgrade-new/payment_channels.so"
CARGO_TARGET_DIR="$build_root/old-sbf" cargo build-sbf \
    --tools-version v1.58 --arch v3 \
    --manifest-path "$source_dir/program/payment_channels/Cargo.toml" \
    --sbf-out-dir "$PWD/target/v1-upgrade-old"
CARGO_TARGET_DIR="$build_root/new-sbf" cargo build-sbf \
    --tools-version v1.58 --arch v3 \
    --manifest-path program/payment_channels/Cargo.toml \
    --sbf-out-dir "$PWD/target/v1-upgrade-new"
run_dir="$(mktemp -d "$PWD/target/v1-upgrade-run.XXXXXX")"
{
    echo "Historical source: $baseline"
    echo "Current source HEAD (working tree may differ): $(git rev-parse HEAD)"
    git diff -- program/payment_channels Cargo.toml Cargo.lock | shasum -a 256
    shasum -a 256 "$UPGRADE_OLD_SO" "$UPGRADE_NEW_SO"
    surfpool --version
} | tee "$run_dir/provenance.txt"
port="${UPGRADE_PORT:-18999}"
export UPGRADE_RPC="http://127.0.0.1:$port"
if curl --noproxy '*' --silent --connect-timeout 1 "$UPGRADE_RPC" >/dev/null 2>&1; then
    echo "Refusing occupied loopback port $port" >&2
    exit 1
fi
pid=""
cleanup() {
    if [[ -n "$pid" ]]; then kill "$pid" 2>/dev/null || true; wait "$pid" 2>/dev/null || true; fi
}
trap cleanup EXIT INT TERM
surfpool start --offline --no-deploy --no-tui --no-studio --host 127.0.0.1 \
    --airdrop-amount 0 --slot-time 10 --port "$port" --ws-port "$((port + 1))" \
    --log-path "$run_dir/logs" >"$run_dir/surfpool.log" 2>&1 &
pid=$!
ready=0
for _ in {1..100}; do
    if curl --noproxy '*' --silent --fail --max-time 1 \
        -H 'Content-Type: application/json' \
        -d '{"jsonrpc":"2.0","id":1,"method":"getHealth"}' \
        "$UPGRADE_RPC" | grep -q '"ok"'; then ready=1; break; fi
    kill -0 "$pid" 2>/dev/null || { cat "$run_dir/surfpool.log"; exit 1; }
    sleep .1
done
[[ "$ready" == 1 ]] || { cat "$run_dir/surfpool.log"; exit 1; }
CARGO_TARGET_DIR="$build_root/host" cargo run --offline \
    --manifest-path scripts/v1-v2-upgrade-e2e/Cargo.toml 2>&1 | tee "$run_dir/result.txt"
echo "Binary reload proof and artifact hashes: $run_dir"
