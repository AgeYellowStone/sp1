use std::{
    env, fs,
    path::{Path, PathBuf},
    time::Instant,
};

use sp1_sdk::prelude::*;
use sp1_sdk::ProverClient;

use rwa_dex_batch_script::{
    codec::{self, batch_settlement_calldata_file, encode_public_values},
    fixtures,
    preflight::{
        BatchInput, BatchSnapshot, Multicall3Provider, PreflightValidator, StaticSnapshotProvider,
    },
};

const ELF: sp1_sdk::Elf = include_elf!("rwa-dex-batch-program");

fn load_input() -> BatchInput {
    match env::var("BATCH_INPUT_PATH") {
        Ok(path) => {
            let content = fs::read_to_string(&path).unwrap_or_else(|error| {
                panic!("failed to read BATCH_INPUT_PATH={path}: {error}");
            });
            serde_json::from_str::<BatchInput>(&content).expect("invalid BatchInput JSON")
        }
        Err(_) => fixtures::synthetic_batch(1),
    }
}

fn use_live_rpc() -> bool {
    env::var("PREFLIGHT_RPC_URL").is_ok() || env::var("ETH_RPC_URL").is_ok()
}

fn proof_mode() -> String {
    env::var("SP1_PROOF_MODE").unwrap_or_else(|_| "groth16".to_owned()).to_lowercase()
}

fn write_artifacts(
    output_dir: &Path,
    mode: &str,
    vkey: &[u8],
    public_values: &[u8],
    proof_bytes: &[u8],
    trades: &[rwa_dex_batch_script::preflight::TradeSettlement],
    setup_ms: u128,
    prove_ms: u128,
    cycles: u64,
    order_count: usize,
) {
    fs::create_dir_all(output_dir).expect("failed to create output directory");
    let calldata_file = batch_settlement_calldata_file(vkey, public_values, proof_bytes, trades);
    let calldata = hex::decode(calldata_file.calldata.trim_start_matches("0x"))
        .expect("calldata hex decode failed");
    fs::write(output_dir.join("proof.bin"), proof_bytes).expect("failed to write proof");
    fs::write(output_dir.join("public-values.bin"), public_values)
        .expect("failed to write public values");
    fs::write(output_dir.join("batch-settlement-calldata.bin"), &calldata)
        .expect("failed to write batch calldata");
    fs::write(output_dir.join("proof.hex"), hex::encode(proof_bytes))
        .expect("failed to write proof hex");
    fs::write(output_dir.join("public-values.hex"), hex::encode(public_values))
        .expect("failed to write public values hex");
    fs::write(output_dir.join("batch-settlement-calldata.hex"), hex::encode(&calldata))
        .expect("failed to write batch calldata hex");
    fs::write(
        output_dir.join("batch_settlement_calldata.json"),
        serde_json::to_vec_pretty(&calldata_file).expect("failed to encode calldata JSON"),
    )
    .expect("failed to write calldata JSON");
    let metrics = serde_json::json!({
        "proof_mode": mode,
        "setup_ms": setup_ms,
        "proving_ms": prove_ms,
        "cycles": cycles,
        "order_count": order_count,
        "trade_count": trades.len(),
        "proof_bytes": proof_bytes.len(),
        "public_values_bytes": public_values.len(),
        "batch_calldata_bytes": calldata.len(),
    });
    fs::write(output_dir.join("metrics.json"), serde_json::to_vec_pretty(&metrics).unwrap())
        .expect("failed to write metrics");
    println!("program vkey: 0x{}", hex::encode(vkey));
    println!("proof mode: {mode}");
    println!("orders: {order_count}, trades: {}", trades.len());
    println!("setup ms: {setup_ms}, proving ms: {prove_ms}");
    println!("artifacts: {}", output_dir.display());
}

#[tokio::main]
async fn main() {
    sp1_sdk::utils::setup_logger();
    let output_dir = PathBuf::from(
        env::var("SP1_OUTPUT_DIR").unwrap_or_else(|_| "proofs/rwa-dex-batch".to_owned()),
    );
    let raw_batch = load_input();
    let report = if use_live_rpc() {
        let provider = Multicall3Provider::from_env()
            .expect("PREFLIGHT_RPC_URL or ETH_RPC_URL is required for a live batch");
        PreflightValidator::new(provider)
            .validate_and_prune(&raw_batch)
            .await
            .expect("pre-flight validation failed")
    } else {
        let snapshot = BatchSnapshot::sufficient_for(&raw_batch);
        PreflightValidator::new(StaticSnapshotProvider::new(snapshot))
            .validate_and_prune(&raw_batch)
            .await
            .expect("synthetic pre-flight validation failed")
    };

    fs::create_dir_all(&output_dir).expect("failed to create output directory");
    let clean_path = env::var("CLEAN_BATCH_PATH")
        .map(PathBuf::from)
        .unwrap_or_else(|_| output_dir.join("clean_batch.json"));
    fs::write(
        &clean_path,
        serde_json::to_vec_pretty(&report.clean_batch).expect("failed to encode clean batch"),
    )
    .expect("failed to write clean batch");
    for rejected in &report.rejected {
        println!("pre-flight pruned trade {}: {}", rejected.index, rejected.reason);
    }
    println!(
        "pre-flight: kept {}/{} trades; clean batch: {}",
        report.clean_batch.trades.len(),
        report.checked_trades,
        clean_path.display()
    );
    if !report.should_prove() {
        println!("pre-flight: no valid trades remain; SP1 prover was not started");
        return;
    }

    let public_values = encode_public_values(&report.clean_batch);
    assert_eq!(
        public_values.len(),
        codec::PUBLIC_VALUES_LEN,
        "unexpected batch public value length"
    );
    let mode = proof_mode();
    if mode == "skip" {
        write_artifacts(
            &output_dir,
            &mode,
            &[0u8; 32],
            &public_values,
            &[0u8],
            &report.clean_batch.trades,
            0,
            0,
            0,
            report.clean_batch.orders.len(),
        );
        return;
    }

    let mut stdin = SP1Stdin::new();
    stdin.write(&report.clean_batch);
    let client = ProverClient::from_env().await;
    let setup_start = Instant::now();
    let proving_key = client.setup(ELF).await.expect("SP1 setup failed");
    let setup_ms = setup_start.elapsed().as_millis();
    let (executed_public_values, execution_report) =
        client.execute(ELF, stdin.clone()).await.expect("SP1 execution failed");
    let cycles =
        execution_report.total_instruction_count() + execution_report.total_syscall_count();
    if mode == "execute" {
        let executed = executed_public_values.as_slice();
        assert_eq!(executed, public_values.as_slice(), "guest public values mismatch host codec");
        write_artifacts(
            &output_dir,
            &mode,
            &proving_key.verifying_key().bytes32_raw(),
            executed,
            &[0u8],
            &report.clean_batch.trades,
            setup_ms,
            0,
            cycles,
            report.clean_batch.orders.len(),
        );
        return;
    }

    let prove_start = Instant::now();
    let proof = match mode.as_str() {
        "groth16" => {
            client.prove(&proving_key, stdin).groth16().await.expect("Groth16 proving failed")
        }
        "plonk" => client.prove(&proving_key, stdin).plonk().await.expect("Plonk proving failed"),
        unsupported => {
            panic!("unsupported SP1_PROOF_MODE={unsupported}; use skip, execute, plonk, or groth16")
        }
    };
    let prove_ms = prove_start.elapsed().as_millis();
    client.verify(&proof, proving_key.verifying_key(), None).expect("local proof verification failed");

    let proof_bytes = proof.bytes();
    let proven_public_values = proof.public_values.as_slice();
    assert_eq!(
        proven_public_values.len(),
        codec::PUBLIC_VALUES_LEN,
        "unexpected batch public value length"
    );
    write_artifacts(
        &output_dir,
        &mode,
        &proving_key.verifying_key().bytes32_raw(),
        proven_public_values,
        &proof_bytes,
        &report.clean_batch.trades,
        setup_ms,
        prove_ms,
        cycles,
        report.clean_batch.orders.len(),
    );
}
