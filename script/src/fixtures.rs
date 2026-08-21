use std::path::PathBuf;

use k256::ecdsa::SigningKey;

use crate::preflight::{
    order_hash, orderbook_root, Address, BatchInput, KycProof, Order, TradeSettlement, Word,
    MAX_ORDERS, MAX_TRADES,
};

pub const CHAIN_ID: u64 = 421614;
pub const BATCH_TIMESTAMP: u64 = 1_700_000_000;
pub const SETTLEMENT: Address = [0x40; 20];
pub const ROUTER: Address = [0x10; 20];
pub const IDENTITY_REGISTRY: Address = [0x50; 20];
pub const TOKEN_IN: Address = [0x20; 20];
pub const TOKEN_OUT: Address = [0x30; 20];
pub const AMOUNT_IN: u64 = 100;
pub const AMOUNT_OUT: u64 = 200;
pub const FIXTURE_SIZES: [usize; 3] = [10, 50, 100];

pub fn fixtures_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("fixtures")
}

pub fn fixture_path(trade_count: usize) -> PathBuf {
    fixtures_dir().join(format!("batch_{trade_count}.json"))
}

pub fn fixture_calldata_path(trade_count: usize) -> PathBuf {
    fixtures_dir().join(format!("batch_{trade_count}_calldata.json"))
}

pub fn pair_count_for(trade_count: usize) -> usize {
    assert!(trade_count > 0 && trade_count <= MAX_TRADES, "invalid trade count");
    trade_count.min(MAX_ORDERS / 2)
}

pub fn synthetic_batch(trade_count: usize) -> BatchInput {
    build_synthetic_batch(trade_count, false)
}

/// Same-size book as `synthetic_batch`, but every pair uses unique tokens so
/// reordering trades cannot trip the same-price FIFO rule.
pub fn synthetic_independent_markets(trade_count: usize) -> BatchInput {
    build_synthetic_batch(trade_count, true)
}

fn pair_tokens(index: usize, unique_markets: bool) -> (Address, Address) {
    if !unique_markets {
        return (TOKEN_IN, TOKEN_OUT);
    }
    let mut token_in = TOKEN_IN;
    let mut token_out = TOKEN_OUT;
    token_in[18] = index as u8;
    token_out[18] = index as u8;
    (token_in, token_out)
}

fn build_synthetic_batch(trade_count: usize, unique_markets: bool) -> BatchInput {
    let pair_count = pair_count_for(trade_count);
    let fills_capacity = trade_count.div_ceil(pair_count);
    let making_in = AMOUNT_IN * fills_capacity as u64;
    let making_out = AMOUNT_OUT * fills_capacity as u64;

    let mut keys = Vec::with_capacity(pair_count);
    let mut addresses = Vec::with_capacity(pair_count * 2);
    for index in 0..pair_count {
        let seller_key =
            SigningKey::from_bytes((&[(index as u8).wrapping_add(1); 32]).into()).unwrap();
        let buyer_key =
            SigningKey::from_bytes((&[(index as u8).wrapping_add(101); 32]).into()).unwrap();
        addresses.push(address_from_key(&seller_key));
        addresses.push(address_from_key(&buyer_key));
        keys.push((seller_key, buyer_key));
    }

    let leaves = addresses.iter().map(|address| keccak256(address)).collect::<Vec<_>>();
    let (kyc_root, proofs) = build_merkle(&leaves);
    let kyc_merkle_proofs = addresses
        .iter()
        .enumerate()
        .map(|(index, subject)| KycProof { subject: *subject, siblings: proofs[index].clone() })
        .collect::<Vec<_>>();

    let mut batch = BatchInput {
        chain_id: CHAIN_ID,
        batch_timestamp: BATCH_TIMESTAMP,
        verifying_contract: SETTLEMENT,
        limit_order_protocol: ROUTER,
        identity_registry: IDENTITY_REGISTRY,
        kyc_root,
        orderbook_root: [0u8; 32],
        orders: Vec::with_capacity(pair_count * 2),
        trades: Vec::with_capacity(trade_count),
        kyc_merkle_proofs,
    };

    for index in 0..pair_count {
        let seller = addresses[index * 2];
        let buyer = addresses[index * 2 + 1];
        let (token_in, token_out) = pair_tokens(index, unique_markets);
        batch.orders.push(Order {
            salt: word((index * 2 + 1) as u64),
            maker: seller,
            receiver: seller,
            maker_asset: token_in,
            taker_asset: token_out,
            making_amount: word(making_in),
            taking_amount: word(making_out),
            maker_traits: multiple_fill_traits((index as u8).wrapping_add(1)),
            signature: Vec::new(),
            kyc_proof_index: (index * 2) as u32,
            arrival_timestamp: (index as u64) + 1,
        });
        batch.orders.push(Order {
            salt: word((index * 2 + 2) as u64),
            maker: buyer,
            receiver: buyer,
            maker_asset: token_out,
            taker_asset: token_in,
            making_amount: word(making_out),
            taking_amount: word(making_in),
            maker_traits: multiple_fill_traits((index as u8).wrapping_add(1)),
            signature: Vec::new(),
            kyc_proof_index: (index * 2 + 1) as u32,
            arrival_timestamp: (index as u64) + 1,
        });
    }

    for pair in 0..pair_count {
        if batch.trades.len() >= trade_count {
            break;
        }
        let seller = addresses[pair * 2];
        let buyer = addresses[pair * 2 + 1];
        let (token_in, token_out) = pair_tokens(pair, unique_markets);
        for _ in 0..fills_capacity {
            if batch.trades.len() >= trade_count {
                break;
            }
            batch.trades.push(TradeSettlement {
                maker: seller,
                taker: buyer,
                token_in,
                token_out,
                amount_in: word(AMOUNT_IN),
                amount_out: word(AMOUNT_OUT),
                maker_order_index: (pair * 2) as u32,
                taker_order_index: (pair * 2 + 1) as u32,
            });
        }
    }

    for index in 0..pair_count {
        let seller_order = batch.orders[index * 2].clone();
        let buyer_order = batch.orders[index * 2 + 1].clone();
        batch.orders[index * 2].signature = sign_order(&batch, &seller_order, &keys[index].0);
        batch.orders[index * 2 + 1].signature = sign_order(&batch, &buyer_order, &keys[index].1);
    }

    let hashes = batch.orders.iter().map(|order| order_hash(&batch, order)).collect::<Vec<_>>();
    batch.orderbook_root = orderbook_root(&hashes);
    batch
}

fn multiple_fill_traits(nonce: u8) -> Word {
    let mut traits = [0u8; 32];
    // ALLOW_MULTIPLE_FILLS (bit 254) with partial fills enabled so the remaining
    // invalidator path is used and the same order can back more than one trade.
    traits[0] = 0x40;
    traits[16] = nonce;
    traits
}

fn word(value: u64) -> Word {
    let mut output = [0u8; 32];
    output[24..].copy_from_slice(&value.to_be_bytes());
    output
}

fn keccak256(bytes: &[u8]) -> Word {
    use tiny_keccak::{Hasher, Keccak};

    let mut hasher = Keccak::v256();
    hasher.update(bytes);
    let mut digest = [0u8; 32];
    hasher.finalize(&mut digest);
    digest
}

fn address_from_key(key: &SigningKey) -> Address {
    let encoded = key.verifying_key().to_encoded_point(false);
    let digest = keccak256(&encoded.as_bytes()[1..]);
    digest[12..].try_into().unwrap()
}

fn sign_order(input: &BatchInput, order: &Order, key: &SigningKey) -> Vec<u8> {
    let digest = order_hash(input, order);
    let (signature, recovery_id) = key.sign_prehash_recoverable(&digest).unwrap();
    let mut output = signature.to_bytes().to_vec();
    output.push(recovery_id.to_byte() + 27);
    output
}

fn sorted_pair(left: Word, right: Word) -> Word {
    let mut pair = [0u8; 64];
    if left <= right {
        pair[..32].copy_from_slice(&left);
        pair[32..].copy_from_slice(&right);
    } else {
        pair[..32].copy_from_slice(&right);
        pair[32..].copy_from_slice(&left);
    }
    keccak256(&pair)
}

fn build_merkle(leaves: &[Word]) -> (Word, Vec<Vec<Word>>) {
    let mut levels = vec![leaves.to_vec()];
    while levels.last().unwrap().len() > 1 {
        let current = levels.last().unwrap();
        let mut next = Vec::with_capacity(current.len().div_ceil(2));
        let mut index = 0;
        while index < current.len() {
            let right = if index + 1 < current.len() { current[index + 1] } else { current[index] };
            next.push(sorted_pair(current[index], right));
            index += 2;
        }
        levels.push(next);
    }
    let root = levels.last().unwrap()[0];
    let mut proofs = Vec::with_capacity(leaves.len());
    for leaf_index in 0..leaves.len() {
        let mut index = leaf_index;
        let mut siblings = Vec::new();
        for level in &levels[..levels.len() - 1] {
            let sibling_index =
                if index % 2 == 0 { (index + 1).min(level.len() - 1) } else { index - 1 };
            siblings.push(level[sibling_index]);
            index /= 2;
        }
        proofs.push(siblings);
    }
    (root, proofs)
}
