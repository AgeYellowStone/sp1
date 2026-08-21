use crate::{BatchInput, TradeSettlement};

pub const PUBLIC_VALUES_LEN: usize = 184;

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
