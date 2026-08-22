#!/usr/bin/env bash
# Build the RWA DEX SP1 guest, generate synthetic batch fixtures if needed,
# and produce Groth16/Plonk (or skip/execute) artifacts that feed
# SP1BatchSettlement.executeBatchWithZKProof.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SP1_SCRIPT="${ROOT}/script"
LOP="${LOP:-${ROOT}/../limit-order-protocol}"

BATCH_SIZE="${BATCH_SIZE:-10}"
SP1_PROOF_MODE="${SP1_PROOF_MODE:-groth16}"
SP1_PROVER="${SP1_PROVER:-cpu}"
RUN_HARDHAT="${RUN_HARDHAT:-0}"

case "${BATCH_SIZE}" in
  10|50|100) ;;
  *)
    echo "BATCH_SIZE must be 10, 50, or 100 (got ${BATCH_SIZE})" >&2
    exit 1
    ;;
esac

case "${SP1_PROOF_MODE}" in
  skip|execute|groth16|plonk) ;;
  *)
    echo "SP1_PROOF_MODE must be skip, execute, groth16, or plonk" >&2
    exit 1
    ;;
esac

if [[ "${SP1_PROOF_MODE}" == "groth16" || "${SP1_PROOF_MODE}" == "plonk" ]]; then
  if [[ "${BATCH_SIZE}" -ge 50 ]]; then
    echo "warning: ${SP1_PROOF_MODE} for ${BATCH_SIZE} trades on CPU can take a very long time" >&2
  fi
fi

need() {
  if ! command -v "$1" >/dev/null 2>&1; then
    echo "missing dependency: $1" >&2
    echo "install Rust from https://rustup.rs and SP1 with:" >&2
    echo "  curl -L https://sp1.succinct.xyz | bash && sp1up" >&2
    exit 1
  fi
}

need cargo
need rustc

if [[ -d "${HOME}/.sp1/bin" ]]; then
  export PATH="${HOME}/.sp1/bin:${PATH}"
fi

if ! command -v cargo-prove >/dev/null 2>&1; then
  echo "cargo-prove not found on PATH. Install SP1 before Groth16/Plonk proving:" >&2
  echo "  curl -L https://sp1.succinct.xyz | bash" >&2
  echo "  sp1up" >&2
  if [[ "${SP1_PROOF_MODE}" == "groth16" || "${SP1_PROOF_MODE}" == "plonk" ]]; then
    exit 1
  fi
fi

cd "${SP1_SCRIPT}"

if [[ ! -f "fixtures/batch_${BATCH_SIZE}.json" ]]; then
  echo "generating synthetic fixtures"
  cargo run --release --no-default-features --bin gen_fixtures
fi

PROVE_FEATURES="sp1"
if [[ "${SP1_PROVER}" == "cuda" ]]; then
  PROVE_FEATURES="sp1,cuda"
fi

echo "building prove host (SP1 guest via build.rs) features=${PROVE_FEATURES}"
cargo build --release --bin prove --features "${PROVE_FEATURES}"

export BATCH_INPUT_PATH="${SP1_SCRIPT}/fixtures/batch_${BATCH_SIZE}.json"
export SP1_PROOF_MODE
export SP1_PROVER
export SP1_OUTPUT_DIR="${SP1_SCRIPT}/proofs/batch_${BATCH_SIZE}"
unset PREFLIGHT_RPC_URL || true
unset ETH_RPC_URL || true

echo "proving batch_${BATCH_SIZE} mode=${SP1_PROOF_MODE} prover=${SP1_PROVER} features=${PROVE_FEATURES}"
cargo run --release --bin prove --features "${PROVE_FEATURES}"

PUBLIC_VALUES="${SP1_OUTPUT_DIR}/public-values.bin"
CALLDATA_JSON="${SP1_OUTPUT_DIR}/batch_settlement_calldata.json"

if [[ ! -f "${PUBLIC_VALUES}" ]]; then
  echo "missing ${PUBLIC_VALUES}" >&2
  exit 1
fi
PV_LEN="$(wc -c < "${PUBLIC_VALUES}" | tr -d ' ')"
if [[ "${PV_LEN}" != "184" ]]; then
  echo "public-values.bin must be 184 bytes (got ${PV_LEN})" >&2
  exit 1
fi

PYTHON_BIN="python3"
if ! command -v python3 >/dev/null 2>&1; then
  PYTHON_BIN="python"
fi
"${PYTHON_BIN}" - "${CALLDATA_JSON}" "${BATCH_SIZE}" <<'PY'
import json, sys
path, expected = sys.argv[1], int(sys.argv[2])
with open(path, encoding="utf-8") as handle:
    data = json.load(handle)
required = ("function", "public_values", "proof_bytes", "trades", "calldata")
missing = [key for key in required if key not in data]
if missing:
    raise SystemExit(f"calldata JSON missing {missing}")
if "executeBatchWithZKProof" not in data["function"]:
    raise SystemExit(f"unexpected function {data['function']}")
if len(data["trades"]) != expected:
    raise SystemExit(f"expected {expected} trades, got {len(data['trades'])}")
trade = data["trades"][0]
for key in ("maker", "taker", "tokenIn", "tokenOut", "amountIn", "amountOut"):
    if key not in trade:
        raise SystemExit(f"trade object missing {key} (Solidity camelCase required)")
print(f"ok: {path} trades={len(data['trades'])} function={data['function']}")
PY

echo
echo "Linux one-liners:"
echo "  ./scripts/verify_linux.sh"
echo "  BATCH_SIZE=10 SP1_PROOF_MODE=groth16 ./scripts/verify_linux.sh"
echo "  BATCH_SIZE=10 SP1_PROOF_MODE=plonk ./scripts/verify_linux.sh"
echo "  BATCH_SIZE=10 SP1_PROOF_MODE=skip ./scripts/verify_linux.sh"
echo "  cargo test --manifest-path script/Cargo.toml --no-default-features --tests"
echo "  cd \"${LOP}\" && npx hardhat test test/SP1BatchGasBenchmark.test.js"

if [[ "${RUN_HARDHAT}" == "1" ]]; then
  if [[ ! -d "${LOP}/node_modules" ]]; then
    echo "limit-order-protocol node_modules missing; skip Hardhat" >&2
    exit 1
  fi
  cd "${LOP}"
  if command -v yarn >/dev/null 2>&1; then
    yarn hardhat test test/SP1BatchGasBenchmark.test.js
  else
    npx hardhat test test/SP1BatchGasBenchmark.test.js
  fi
fi
