use std::sync::{
    atomic::{AtomicUsize, Ordering},
    Arc,
};

use async_trait::async_trait;
use k256::ecdsa::SigningKey;
use rwa_dex_batch_script::preflight::{
    order_hash, orderbook_root, Address, BatchInput, BatchSnapshot, KycProof, Order,
    PreflightError, PreflightValidator, SnapshotProvider, TradeSettlement, Word,
};
use rwa_dex_batch_script::preflight::{MAX_ORDERS, MAX_TRADES};
use tiny_keccak::{Hasher, Keccak};

const SETTLEMENT: Address = [0x40; 20];
const ROUTER: Address = [0x10; 20];
const IDENTITY_REGISTRY: Address = [0x50; 20];
const TOKEN_IN: Address = [0x20; 20];
const TOKEN_OUT: Address = [0x30; 20];

#[derive(Clone)]
struct CountingProvider {
    snapshot: BatchSnapshot,
    calls: Arc<AtomicUsize>,
}

#[async_trait]
impl SnapshotProvider for CountingProvider {
    async fn snapshot(&self, _batch: &BatchInput) -> Result<BatchSnapshot, PreflightError> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        Ok(self.snapshot.clone())
    }
}

fn word(value: u64) -> Word {
    let mut output = [0u8; 32];
    output[24..].copy_from_slice(&value.to_be_bytes());
    output
}

fn keccak256(bytes: &[u8]) -> Word {
    let mut hasher = Keccak::v256();
    hasher.update(bytes);
    let mut digest = [0u8; 32];
    hasher.finalize(&mut digest);
    digest
}

fn address_from_key(key: &SigningKey) -> Address {
    let point = key.verifying_key().to_encoded_point(false);
    let digest = keccak256(&point.as_bytes()[1..]);
    digest[12..].try_into().unwrap()
}

fn encode_signature(
    signature: k256::ecdsa::Signature,
    recovery: k256::ecdsa::RecoveryId,
) -> Vec<u8> {
    let mut output = signature.to_bytes().to_vec();
    output.push(recovery.to_byte() + 27);
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
        let mut next = Vec::with_capacity((current.len() + 1) / 2);
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

fn build_batch(count: usize, amount_in: u64, amount_out: u64) -> BatchInput {
    let mut keys = Vec::with_capacity(count * 2);
    let mut addresses = Vec::with_capacity(count * 2);
    for index in 0..count {
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
        chain_id: 421614,
        batch_timestamp: 1_000,
        verifying_contract: SETTLEMENT,
        limit_order_protocol: ROUTER,
        identity_registry: IDENTITY_REGISTRY,
        kyc_root,
        orderbook_root: [0u8; 32],
        orders: Vec::with_capacity(count * 2),
        trades: Vec::with_capacity(count),
        kyc_merkle_proofs,
    };
    for index in 0..count {
        let seller = addresses[index * 2];
        let buyer = addresses[index * 2 + 1];
        let mut seller_traits = [0u8; 32];
        seller_traits[16] = (index as u8) + 1;
        let mut buyer_traits = [0u8; 32];
        buyer_traits[16] = (index as u8) + 1;
        batch.orders.push(Order {
            salt: word((index * 2 + 1) as u64),
            maker: seller,
            receiver: seller,
            maker_asset: TOKEN_IN,
            taker_asset: TOKEN_OUT,
            making_amount: word(amount_in),
            taking_amount: word(amount_out),
            maker_traits: seller_traits,
            signature: Vec::new(),
            kyc_proof_index: (index * 2) as u32,
            arrival_timestamp: 0,
        });
        batch.orders.push(Order {
            salt: word((index * 2 + 2) as u64),
            maker: buyer,
            receiver: buyer,
            maker_asset: TOKEN_OUT,
            taker_asset: TOKEN_IN,
            making_amount: word(amount_out),
            taking_amount: word(amount_in),
            maker_traits: buyer_traits,
            signature: Vec::new(),
            kyc_proof_index: (index * 2 + 1) as u32,
            arrival_timestamp: 0,
        });
        batch.trades.push(TradeSettlement {
            maker: seller,
            taker: buyer,
            token_in: TOKEN_IN,
            token_out: TOKEN_OUT,
            amount_in: word(amount_in),
            amount_out: word(amount_out),
            maker_order_index: (index * 2) as u32,
            taker_order_index: (index * 2 + 1) as u32,
        });
    }
    for index in 0..count {
        let seller_order = batch.orders[index * 2].clone();
        let buyer_order = batch.orders[index * 2 + 1].clone();
        let (seller_signature, _) =
            keys[index].0.sign_prehash_recoverable(&order_hash(&batch, &seller_order)).unwrap();
        let (buyer_signature, _) =
            keys[index].1.sign_prehash_recoverable(&order_hash(&batch, &buyer_order)).unwrap();
        let (_, seller_recovery) =
            keys[index].0.sign_prehash_recoverable(&order_hash(&batch, &seller_order)).unwrap();
        let (_, buyer_recovery) =
            keys[index].1.sign_prehash_recoverable(&order_hash(&batch, &buyer_order)).unwrap();
        batch.orders[index * 2].signature = encode_signature(seller_signature, seller_recovery);
        batch.orders[index * 2 + 1].signature = encode_signature(buyer_signature, buyer_recovery);
    }
    let hashes = batch.orders.iter().map(|order| order_hash(&batch, order)).collect::<Vec<_>>();
    batch.orderbook_root = orderbook_root(&hashes);
    batch
}

fn snapshot_for(batch: &BatchInput, balance_in: u64, balance_out: u64) -> BatchSnapshot {
    let mut snapshot = BatchSnapshot::default();
    for trade in &batch.trades {
        snapshot.set_verified(trade.maker, true);
        snapshot.set_verified(trade.taker, true);
        snapshot.set_asset(trade.maker, trade.token_in, word(balance_in), word(balance_in));
        snapshot.set_asset(trade.taker, trade.token_out, word(balance_out), word(balance_out));
        snapshot.set_bit_invalidator(trade.maker, 0, [0u8; 32]);
        snapshot.set_bit_invalidator(trade.taker, 0, [0u8; 32]);
    }
    snapshot
}

async fn validate(
    batch: BatchInput,
    snapshot: BatchSnapshot,
) -> (rwa_dex_batch_script::preflight::PreflightReport, Arc<AtomicUsize>) {
    let calls = Arc::new(AtomicUsize::new(0));
    let provider = CountingProvider { snapshot, calls: calls.clone() };
    let report = PreflightValidator::new(provider).validate_and_prune(&batch).await.unwrap();
    (report, calls)
}

#[tokio::test]
async fn scenario_a_keeps_ten_valid_trades_and_uses_one_snapshot() {
    let batch = build_batch(10, 10, 20);
    let snapshot = snapshot_for(&batch, 100, 200);
    let (report, calls) = validate(batch, snapshot).await;
    assert_eq!(report.clean_batch.trades.len(), 10);
    assert!(report.rejected.is_empty());
    assert!(report.should_prove());
    assert_eq!(calls.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn scenario_b_prunes_two_kyc_failures() {
    let batch = build_batch(10, 10, 20);
    let mut snapshot = snapshot_for(&batch, 100, 200);
    snapshot.set_verified(batch.trades[2].maker, false);
    snapshot.set_verified(batch.trades[7].taker, false);
    let (report, _) = validate(batch, snapshot).await;
    assert_eq!(report.clean_batch.trades.len(), 8);
    assert_eq!(report.rejected.len(), 2);
}

#[tokio::test]
async fn scenario_c_tracks_the_same_maker_cumulatively() {
    let mut batch = build_batch(3, 40, 40);
    let maker = batch.trades[0].maker;
    for trade in &mut batch.trades {
        trade.maker = maker;
    }
    let signing_batch = batch.clone();
    for (index, order) in batch.orders.iter_mut().step_by(2).enumerate() {
        order.maker = maker;
        order.kyc_proof_index = 0;
        order.maker_traits[16] = (index as u8) + 1;
        let key = SigningKey::from_bytes((&[1u8; 32]).into()).unwrap();
        let (signature, recovery_id) =
            key.sign_prehash_recoverable(&order_hash(&signing_batch, order)).unwrap();
        order.signature = encode_signature(signature, recovery_id);
    }
    let hashes = batch.orders.iter().map(|order| order_hash(&batch, order)).collect::<Vec<_>>();
    batch.orderbook_root = orderbook_root(&hashes);
    let mut snapshot = snapshot_for(&batch, 80, 120);
    snapshot.set_asset(maker, TOKEN_IN, word(80), word(80));
    snapshot.set_verified(maker, true);
    let (report, _) = validate(batch, snapshot).await;
    assert_eq!(report.clean_batch.trades.len(), 2);
    assert_eq!(report.rejected.len(), 1);
}

#[tokio::test]
async fn scenario_d_empty_batch_skips_prover() {
    let batch = build_batch(2, 10, 20);
    let mut snapshot = snapshot_for(&batch, 20, 40);
    for trade in &batch.trades {
        snapshot.set_verified(trade.maker, false);
        snapshot.set_verified(trade.taker, false);
    }
    let (report, _) = validate(batch, snapshot).await;
    assert!(report.clean_batch.trades.is_empty());
    assert!(!report.should_prove());
}

#[test]
fn batch_limits_match_guest_contract() {
    assert_eq!(MAX_ORDERS, 128);
    assert_eq!(MAX_TRADES, 256);
}
