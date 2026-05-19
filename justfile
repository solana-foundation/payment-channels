# Payment Channels — build + IDL + client automation.

set shell := ["bash", "-uc"]

program_dir       := "program/payment_channels"
ts_client_dir     := "clients/typescript"
deploy_key        := "keys/payment_channels-keypair.json"
target_deploy_key := "target/deploy/payment_channels-keypair.json"
idl_file          := program_dir / "idl/payment_channels.json"
raw_idl_file      := program_dir / "idl/payment_channels.raw.json"

default:
    @just --list

# ---------- setup ----------

# One-shot: generate the program keypair (if missing) and install JS deps.
setup: init-keys
    #!/usr/bin/env bash
    set -euo pipefail
    for cmd in pnpm cargo solana-keygen just; do
        command -v "$cmd" >/dev/null || { echo "missing: $cmd"; exit 1; }
    done
    pnpm install
    echo "✓ setup complete; program id: $(solana-keygen pubkey {{deploy_key}})"

program-id:
    @solana-keygen pubkey "{{deploy_key}}"

# Generate the program keypair on first run (only if missing). Committed to
# the repo so every developer, CI run, and test deploys to the same address.
init-keys:
    #!/usr/bin/env bash
    set -euo pipefail
    mkdir -p keys
    if [[ ! -f "{{deploy_key}}" ]]; then
        solana-keygen new --no-bip39-passphrase -o "{{deploy_key}}"
        echo "✓ generated {{deploy_key}} — update declare_id! in lib.rs to $(solana-keygen pubkey {{deploy_key}})"
    fi

prepare-deploy-keys: init-keys
    #!/usr/bin/env bash
    set -euo pipefail
    mkdir -p target/deploy
    cp "{{deploy_key}}" "{{target_deploy_key}}"

# ---------- build ----------

build: build-program build-client

build-program: prepare-deploy-keys
    cd {{program_dir}} && cargo build-sbf
    @echo "✓ program built"

# Raw IDL is emitted by build.rs, gated on the `idl` feature so plain
# `cargo build` / `cargo build-sbf` don't touch it. Rust Codama macros define
# the wire types; the remaining visitor only adds distribute's dynamic account
# tail and writes the committed IDL.
generate-idl:
    cd {{program_dir}} && GENERATE_IDL="$RANDOM-$(date +%s)" cargo build --features idl
    pnpm exec codama run idl --idl {{raw_idl_file}}
    @echo "✓ IDL: {{idl_file}}"

generate-client: generate-idl
    pnpm run generate
    @echo "✓ clients generated"

build-client: generate-client
    cd {{ts_client_dir}} && pnpm run build
    @echo "✓ ts client built"

# ---------- test ----------

test: test-program

test-program: generate-client
    cd {{program_dir}} && cargo test-sbf

# Run tests with CU profiling enabled. The `instructions` test binary
# writes a single `cu_report.md` next to Cargo.toml on exit; CI posts it
# as the PR comment. Local: `cat {{program_dir}}/cu_report.md`.
test-and-benchmark: generate-client
    cd {{program_dir}} && \
        CU_REPORT=1 CU_REPORT_DATE="$(date -u +%Y-%m-%d)" cargo test-sbf

# Focused event-engine end-to-end run (litesvm). Loads the compiled .so
# and exercises the self-CPI Anchor-event wire format via the `open`
# instruction plus the `emit_event` validation surface.
events-e2e:
    cd {{program_dir}} && cargo test-sbf --test instructions event_engine_e2e::

# ---------- quality ----------

check: generate-client
    cargo fmt --all -- --check
    cargo clippy --all-targets -- -D warnings
    pnpm run format:check
    cd {{ts_client_dir}} && pnpm run typecheck

fmt:
    cargo fmt --all
    pnpm run format

# ---------- misc ----------

clean:
    rm -rf target
    rm -rf {{program_dir}}/idl
    rm -rf clients/rust/src/generated
    rm -rf clients/typescript/src/generated
    rm -rf clients/typescript/dist
    rm -rf node_modules clients/*/node_modules
