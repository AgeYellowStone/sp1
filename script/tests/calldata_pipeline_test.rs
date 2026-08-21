use std::fs;

use rwa_dex_batch_script::{
    codec::{
        batch_settlement_calldata_file, encode_execute_batch_calldata, encode_public_values,
        encode_trades_abi, execute_batch_selector, trades_hash, BatchSettlementCalldataFile,
        EXECUTE_BATCH_SIGNATURE, PUBLIC_VALUES_LEN,
    },
    fixtures::{
        fixture_calldata_path, fixture_path, pair_count_for, synthetic_batch,
        synthetic_independent_markets, FIXTURE_SIZES, AMOUNT_IN, AMOUNT_OUT,
    },
    preflight::{
        BatchInput, BatchSnapshot, PreflightValidator, RejectionReason, StaticSnapshotProvider,
        MAX_ORDERS,
    },
};

async fn assert_clean_preflight(batch: &BatchInput) {
    let snapshot = BatchSnapshot::sufficient_for(batch);
    let report = PreflightValidator::new(StaticSnapshotProvider::new(snapshot))
        .validate_and_prune(batch)
        .await
        .expect("synthetic pre-flight failed");
    assert!(report.rejected.is_empty(), "synthetic fixture was pruned: {:?}", report.rejected);
    assert_eq!(report.clean_batch.trades.len(), batch.trades.len());
    assert!(report.should_prove());
}

fn assert_public_values(batch: &BatchInput) {
    let values = encode_public_values(batch);
    assert_eq!(values.len(), PUBLIC_VALUES_LEN);
    assert_eq!(&values[0..4], b"RWA1");
    assert_eq!(&values[144..148], &(batch.orders.len() as u32).to_be_bytes());
    assert_eq!(&values[148..152], &(batch.trades.len() as u32).to_be_bytes());
    assert_eq!(&values[152..], &trades_hash(&batch.trades));
}

fn assert_calldata_abi(batch: &BatchInput) {
    let public_values = encode_public_values(batch);
    let proof = [0u8];
    let calldata = encode_execute_batch_calldata(&public_values, &proof, &batch.trades);
    assert_eq!(&calldata[..4], &execute_batch_selector());
    let file = batch_settlement_calldata_file(&[0u8; 32], &public_values, &proof, &batch.trades);
    assert_eq!(file.function, EXECUTE_BATCH_SIGNATURE);
    assert_eq!(file.trades.len(), batch.trades.len());
    assert!(file.trades.iter().all(|trade| trade.token_in.starts_with("0x")
        && trade.token_out.starts_with("0x")
        && trade.amount_in.starts_with("0x")
        && trade.amount_out.starts_with("0x")));
    let json = serde_json::to_value(&file).unwrap();
    assert!(json["trades"][0]["tokenIn"].is_string());
    assert!(json["trades"][0].get("token_in").is_none());
    let encoded_trades = encode_trades_abi(&batch.trades);
    assert_eq!(encoded_trades.len(), 64 + batch.trades.len() * 192);
}

#[tokio::test]
async fn synthetic_batches_keep_all_trades_and_encode_solidity_calldata() {
    for trade_count in FIXTURE_SIZES {
        let batch = synthetic_batch(trade_count);
        assert_eq!(batch.trades.len(), trade_count);
        assert_eq!(batch.orders.len(), pair_count_for(trade_count) * 2);
        assert!(batch.orders.len() <= MAX_ORDERS);
        assert_eq!(batch.trades[0].amount_in[24..], AMOUNT_IN.to_be_bytes());
        assert_eq!(batch.trades[0].amount_out[24..], AMOUNT_OUT.to_be_bytes());
        assert_clean_preflight(&batch).await;
        assert_public_values(&batch);
        assert_calldata_abi(&batch);
    }
}

#[tokio::test]
async fn committed_fixtures_round_trip_through_batch_input_and_calldata_json() {
    for trade_count in FIXTURE_SIZES {
        let batch_path = fixture_path(trade_count);
        let calldata_path = fixture_calldata_path(trade_count);
        assert!(batch_path.exists(), "missing {}; run gen_fixtures", batch_path.display());
        assert!(calldata_path.exists(), "missing {}; run gen_fixtures", calldata_path.display());
        let batch: BatchInput =
            serde_json::from_str(&fs::read_to_string(&batch_path).unwrap()).unwrap();
        assert_eq!(batch.trades.len(), trade_count);
        assert_clean_preflight(&batch).await;
        assert_public_values(&batch);
        let file: BatchSettlementCalldataFile =
            serde_json::from_str(&fs::read_to_string(&calldata_path).unwrap()).unwrap();
        assert_eq!(file.function, EXECUTE_BATCH_SIGNATURE);
        assert_eq!(file.trades.len(), trade_count);
        let expected = encode_execute_batch_calldata(
            &encode_public_values(&batch),
            &[0u8],
            &batch.trades,
        );
        let decoded = hex::decode(file.calldata.trim_start_matches("0x")).unwrap();
        assert_eq!(decoded, expected);
        assert_eq!(&decoded[..4], &execute_batch_selector());
    }
}

#[test]
fn execute_batch_selector_matches_canonical_signature() {
    assert_eq!(execute_batch_selector().len(), 4);
    assert_eq!(
        EXECUTE_BATCH_SIGNATURE,
        "executeBatchWithZKProof(bytes,bytes,(address,address,address,address,uint256,uint256)[])"
    );
}

#[tokio::test]
async fn reordering_independent_trades_is_still_accepted() {
    let mut batch = synthetic_independent_markets(2);
    let original_makers = [batch.trades[0].maker, batch.trades[1].maker];
    batch.trades.swap(0, 1);
    assert_ne!(batch.trades[0].maker, original_makers[0]);
    assert_eq!(batch.trades[0].maker, original_makers[1]);
    assert_clean_preflight(&batch).await;
    assert_public_values(&batch);
}

#[tokio::test]
async fn same_price_fifo_fill_in_arrival_order_is_accepted() {
    let batch = synthetic_batch(2);
    assert!(batch.orders[0].arrival_timestamp < batch.orders[2].arrival_timestamp);
    assert_eq!(batch.orders[0].maker_asset, batch.orders[2].maker_asset);
    assert_clean_preflight(&batch).await;
}

#[tokio::test]
async fn same_price_fifo_reorder_is_rejected() {
    let mut batch = synthetic_batch(2);
    batch.trades.swap(0, 1);
    let snapshot = BatchSnapshot::sufficient_for(&batch);
    let report = PreflightValidator::new(StaticSnapshotProvider::new(snapshot))
        .validate_and_prune(&batch)
        .await
        .expect("pre-flight should prune FIFO violations, not abort the batch");
    assert_eq!(report.rejected.len(), 1);
    assert_eq!(report.rejected[0].reason, RejectionReason::FifoViolation);
    assert_eq!(report.clean_batch.trades.len(), 1);
}
