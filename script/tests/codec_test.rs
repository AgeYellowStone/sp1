use rwa_dex_batch_script::{
    codec::{encode_public_values, encode_trades_abi, trades_hash, PUBLIC_VALUES_LEN},
    preflight::{Address, BatchInput, TradeSettlement, Word},
};

fn word(value: u64) -> Word {
    let mut output = [0u8; 32];
    output[24..].copy_from_slice(&value.to_be_bytes());
    output
}

fn trade() -> TradeSettlement {
    TradeSettlement {
        maker: [1u8; 20],
        taker: [2u8; 20],
        token_in: [3u8; 20],
        token_out: [4u8; 20],
        amount_in: word(10),
        amount_out: word(20),
        maker_order_index: 0,
        taker_order_index: 1,
    }
}

#[test]
fn abi_trade_encoding_excludes_private_order_indices() {
    let trades = vec![trade()];
    let encoded = encode_trades_abi(&trades);
    assert_eq!(encoded.len(), 32 + 32 + 6 * 32);
    assert_eq!(&encoded[0..32], &word(32));
    assert_eq!(&encoded[32..64], &word(1));
    let expected: Word =
        hex::decode("06d79d1a7d65919b8a045d4f37c79e1bf61d9c75e24e9744678d429225165809")
            .unwrap()
            .try_into()
            .unwrap();
    assert_eq!(trades_hash(&trades), expected);
}

#[test]
fn public_values_are_fixed_and_pack_the_batch_counts() {
    let trades = vec![trade()];
    let batch = BatchInput {
        chain_id: 421614,
        batch_timestamp: 100,
        verifying_contract: [5u8; 20],
        limit_order_protocol: [6u8; 20],
        identity_registry: [7u8; 20],
        kyc_root: [8u8; 32],
        orderbook_root: [9u8; 32],
        orders: Vec::new(),
        trades,
        kyc_merkle_proofs: Vec::new(),
    };
    let values = encode_public_values(&batch);
    assert_eq!(values.len(), PUBLIC_VALUES_LEN);
    assert_eq!(&values[0..4], b"RWA1");
    assert_eq!(&values[144..148], &0u32.to_be_bytes());
    assert_eq!(&values[148..152], &1u32.to_be_bytes());
    assert_eq!(&values[152..], &trades_hash(&batch.trades));
}

#[test]
fn address_type_remains_twenty_bytes() {
    let address: Address = [0u8; 20];
    assert_eq!(address.len(), 20);
}

#[test]
fn execute_batch_selector_is_stable() {
    use rwa_dex_batch_script::codec::execute_batch_selector;
    assert_eq!(hex::encode(execute_batch_selector()), "13fef750");
}

