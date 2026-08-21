use serde::{Deserialize, Serialize};

use crate::preflight::{Address, BatchInput, TradeSettlement};

pub const PUBLIC_VALUES_LEN: usize = 184;
pub const EXECUTE_BATCH_SIGNATURE: &str =
    "executeBatchWithZKProof(bytes,bytes,(address,address,address,address,uint256,uint256)[])";

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct CalldataTrade {
    pub maker: String,
    pub taker: String,
    #[serde(rename = "tokenIn")]
    pub token_in: String,
    #[serde(rename = "tokenOut")]
    pub token_out: String,
    #[serde(rename = "amountIn")]
    pub amount_in: String,
    #[serde(rename = "amountOut")]
    pub amount_out: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct BatchSettlementCalldataFile {
    pub function: String,
    pub program_vkey: String,
    pub public_values: String,
    pub proof_bytes: String,
    pub calldata: String,
    pub trades: Vec<CalldataTrade>,
}

pub fn encode_trades_abi(trades: &[TradeSettlement]) -> Vec<u8> {
    let mut output = Vec::with_capacity(64 + trades.len() * 192);
    output.extend_from_slice(&u256_word(32));
    output.extend_from_slice(&u256_word(trades.len() as u64));
    for trade in trades {
        output.extend_from_slice(&address_word(&trade.maker));
        output.extend_from_slice(&address_word(&trade.taker));
        output.extend_from_slice(&address_word(&trade.token_in));
        output.extend_from_slice(&address_word(&trade.token_out));
        output.extend_from_slice(&trade.amount_in);
        output.extend_from_slice(&trade.amount_out);
    }
    output
}

pub fn trades_hash(trades: &[TradeSettlement]) -> [u8; 32] {
    keccak256(&encode_trades_abi(trades))
}

pub fn encode_public_values(input: &BatchInput) -> Vec<u8> {
    let mut output = Vec::with_capacity(PUBLIC_VALUES_LEN);
    output.extend_from_slice(b"RWA1");
    output.extend_from_slice(&input.chain_id.to_be_bytes());
    output.extend_from_slice(&input.batch_timestamp.to_be_bytes());
    output.extend_from_slice(&input.verifying_contract);
    output.extend_from_slice(&input.limit_order_protocol);
    output.extend_from_slice(&input.identity_registry);
    output.extend_from_slice(&input.kyc_root);
    output.extend_from_slice(&input.orderbook_root);
    output.extend_from_slice(&(input.orders.len() as u32).to_be_bytes());
    output.extend_from_slice(&(input.trades.len() as u32).to_be_bytes());
    output.extend_from_slice(&trades_hash(&input.trades));
    output
}

pub fn execute_batch_selector() -> [u8; 4] {
    keccak256(EXECUTE_BATCH_SIGNATURE.as_bytes())[..4].try_into().unwrap()
}

pub fn encode_execute_batch_calldata(
    public_values: &[u8],
    proof: &[u8],
    trades: &[TradeSettlement],
) -> Vec<u8> {
    let public_tail_len = 32 + padded_length(public_values.len());
    let proof_tail_len = 32 + padded_length(proof.len());
    let mut args = Vec::with_capacity(96 + public_tail_len + proof_tail_len + 32 + trades.len() * 192);
    args.extend_from_slice(&u256_word(96));
    args.extend_from_slice(&u256_word((96 + public_tail_len) as u64));
    args.extend_from_slice(&u256_word((96 + public_tail_len + proof_tail_len) as u64));
    args.extend_from_slice(&u256_word(public_values.len() as u64));
    args.extend_from_slice(public_values);
    args.resize(args.len() + padded_length(public_values.len()) - public_values.len(), 0);
    args.extend_from_slice(&u256_word(proof.len() as u64));
    args.extend_from_slice(proof);
    args.resize(args.len() + padded_length(proof.len()) - proof.len(), 0);
    args.extend_from_slice(&u256_word(trades.len() as u64));
    for trade in trades {
        args.extend_from_slice(&address_word(&trade.maker));
        args.extend_from_slice(&address_word(&trade.taker));
        args.extend_from_slice(&address_word(&trade.token_in));
        args.extend_from_slice(&address_word(&trade.token_out));
        args.extend_from_slice(&trade.amount_in);
        args.extend_from_slice(&trade.amount_out);
    }
    let mut output = Vec::with_capacity(4 + args.len());
    output.extend_from_slice(&execute_batch_selector());
    output.extend_from_slice(&args);
    output
}

pub fn calldata_trades(trades: &[TradeSettlement]) -> Vec<CalldataTrade> {
    trades
        .iter()
        .map(|trade| CalldataTrade {
            maker: hex_address(&trade.maker),
            taker: hex_address(&trade.taker),
            token_in: hex_address(&trade.token_in),
            token_out: hex_address(&trade.token_out),
            amount_in: format!("0x{}", hex::encode(trade.amount_in)),
            amount_out: format!("0x{}", hex::encode(trade.amount_out)),
        })
        .collect()
}

pub fn batch_settlement_calldata_file(
    program_vkey: &[u8],
    public_values: &[u8],
    proof_bytes: &[u8],
    trades: &[TradeSettlement],
) -> BatchSettlementCalldataFile {
    let calldata = encode_execute_batch_calldata(public_values, proof_bytes, trades);
    BatchSettlementCalldataFile {
        function: EXECUTE_BATCH_SIGNATURE.to_owned(),
        program_vkey: format!("0x{}", hex::encode(program_vkey)),
        public_values: format!("0x{}", hex::encode(public_values)),
        proof_bytes: format!("0x{}", hex::encode(proof_bytes)),
        calldata: format!("0x{}", hex::encode(&calldata)),
        trades: calldata_trades(trades),
    }
}

fn padded_length(length: usize) -> usize {
    length.div_ceil(32) * 32
}

fn hex_address(address: &Address) -> String {
    format!("0x{}", hex::encode(address))
}

fn address_word(address: &[u8; 20]) -> [u8; 32] {
    let mut word = [0u8; 32];
    word[12..].copy_from_slice(address);
    word
}

fn u256_word(value: u64) -> [u8; 32] {
    let mut word = [0u8; 32];
    word[24..].copy_from_slice(&value.to_be_bytes());
    word
}

fn keccak256(bytes: &[u8]) -> [u8; 32] {
    use tiny_keccak::{Hasher, Keccak};

    let mut hasher = Keccak::v256();
    hasher.update(bytes);
    let mut digest = [0u8; 32];
    hasher.finalize(&mut digest);
    digest
}
