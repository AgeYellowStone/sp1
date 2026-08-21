use std::fs;

use rwa_dex_batch_script::{
    codec::{batch_settlement_calldata_file, encode_public_values},
    fixtures::{
        fixture_calldata_path, fixture_path, fixtures_dir, synthetic_batch, FIXTURE_SIZES,
    },
};

fn main() {
    let dir = fixtures_dir();
    fs::create_dir_all(&dir).expect("failed to create fixtures directory");
    for trade_count in FIXTURE_SIZES {
        let batch = synthetic_batch(trade_count);
        assert_eq!(batch.trades.len(), trade_count);
        fs::write(
            fixture_path(trade_count),
            serde_json::to_vec_pretty(&batch).expect("failed to encode BatchInput"),
        )
        .expect("failed to write batch fixture");
        let public_values = encode_public_values(&batch);
        let calldata = batch_settlement_calldata_file(&[0u8; 32], &public_values, &[0u8], &batch.trades);
        fs::write(
            fixture_calldata_path(trade_count),
            serde_json::to_vec_pretty(&calldata).expect("failed to encode calldata fixture"),
        )
        .expect("failed to write calldata fixture");
        println!(
            "wrote batch_{trade_count}.json ({} orders, {} trades) and calldata JSON",
            batch.orders.len(),
            batch.trades.len()
        );
    }
}
