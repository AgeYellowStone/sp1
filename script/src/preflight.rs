use std::{
    collections::{HashMap, HashSet},
    env, fmt,
    sync::Arc,
};

use async_trait::async_trait;
use crypto_bigint::{CheckedAdd, CheckedSub, Encoding, NonZero, U256, U512};
use k256::ecdsa::{RecoveryId, Signature, VerifyingKey};
use reqwest::Client;
use serde::{Deserialize, Serialize};
use serde_json::json;
use thiserror::Error;
use tiny_keccak::{Hasher, Keccak};

pub const ARBITRUM_SEPOLIA_CHAIN_ID: u64 = 421614;
pub const MAX_ORDERS: usize = 128;
pub const MAX_TRADES: usize = 256;
pub const MAX_KYC_PROOF_DEPTH: usize = 64;
pub const MULTICALL3_ADDRESS: Address = [
    0xca, 0x11, 0xbd, 0xe0, 0x59, 0x77, 0xb3, 0x63, 0x11, 0x67, 0x02, 0x88, 0x62, 0xbe, 0x2a, 0x17,
    0x39, 0x76, 0xca, 0x11,
];

const ORDER_TYPE: &[u8] = b"Order(uint256 salt,address maker,address receiver,address makerAsset,address takerAsset,uint256 makingAmount,uint256 takingAmount,uint256 makerTraits)";
const DOMAIN_TYPE: &[u8] =
    b"EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)";
const DOMAIN_NAME: &[u8] = b"1inch Limit Order Protocol";
const DOMAIN_VERSION: &[u8] = b"4";

pub type Address = [u8; 20];
pub type Word = [u8; 32];

#[derive(Clone, Serialize, Deserialize, Debug, PartialEq, Eq)]
pub struct Order {
    pub salt: Word,
    pub maker: Address,
    pub receiver: Address,
    pub maker_asset: Address,
    pub taker_asset: Address,
    pub making_amount: Word,
    pub taking_amount: Word,
    pub maker_traits: Word,
    pub signature: Vec<u8>,
    pub kyc_proof_index: u32,
    #[serde(default)]
    pub arrival_timestamp: u64,
}

#[derive(Clone, Serialize, Deserialize, Debug, PartialEq, Eq)]
pub struct KycProof {
    pub subject: Address,
    pub siblings: Vec<Word>,
}

#[derive(Clone, Serialize, Deserialize, Debug, PartialEq, Eq)]
pub struct TradeSettlement {
    pub maker: Address,
    pub taker: Address,
    pub token_in: Address,
    pub token_out: Address,
    pub amount_in: Word,
    pub amount_out: Word,
    pub maker_order_index: u32,
    pub taker_order_index: u32,
}

#[derive(Clone, Serialize, Deserialize, Debug, PartialEq, Eq)]
pub struct BatchInput {
    pub chain_id: u64,
    pub batch_timestamp: u64,
    pub verifying_contract: Address,
    pub limit_order_protocol: Address,
    pub identity_registry: Address,
    pub kyc_root: Word,
    pub orderbook_root: Word,
    pub orders: Vec<Order>,
    pub trades: Vec<TradeSettlement>,
    pub kyc_merkle_proofs: Vec<KycProof>,
}

#[derive(Clone, Copy, Debug, Hash, PartialEq, Eq)]
pub struct AccountAsset {
    pub owner: Address,
    pub token: Address,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct AssetSnapshot {
    pub balance: Word,
    pub allowance: Word,
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct BatchSnapshot {
    pub verified: HashMap<Address, bool>,
    pub assets: HashMap<AccountAsset, AssetSnapshot>,
    pub bit_invalidators: HashMap<(Address, u64), Word>,
    pub remaining_invalidators: HashMap<(Address, Word), Word>,
}

impl BatchSnapshot {
    pub fn set_verified(&mut self, address: Address, verified: bool) {
        self.verified.insert(address, verified);
    }

    pub fn set_asset(&mut self, owner: Address, token: Address, balance: Word, allowance: Word) {
        self.assets.insert(AccountAsset { owner, token }, AssetSnapshot { balance, allowance });
    }

    pub fn set_bit_invalidator(&mut self, maker: Address, slot: u64, invalidator: Word) {
        self.bit_invalidators.insert((maker, slot), invalidator);
    }

    pub fn set_remaining_invalidator(
        &mut self,
        maker: Address,
        order_hash: Word,
        invalidator: Word,
    ) {
        self.remaining_invalidators.insert((maker, order_hash), invalidator);
    }

    /// Builds a snapshot that covers KYC, cumulative balances/allowances, and
    /// both 1inch invalidator types so synthetic fixtures can skip live RPC.
    pub fn sufficient_for(batch: &BatchInput) -> Self {
        let mut snapshot = Self::default();
        let mut needed: HashMap<AccountAsset, Word> = HashMap::new();
        for trade in &batch.trades {
            snapshot.set_verified(trade.maker, true);
            snapshot.set_verified(trade.taker, true);
            accumulate_word(
                &mut needed,
                AccountAsset { owner: trade.maker, token: trade.token_in },
                trade.amount_in,
            );
            accumulate_word(
                &mut needed,
                AccountAsset { owner: trade.taker, token: trade.token_out },
                trade.amount_out,
            );
        }
        for (key, amount) in needed {
            snapshot.set_asset(key.owner, key.token, amount, amount);
        }
        for order in &batch.orders {
            snapshot.set_bit_invalidator(
                order.maker,
                nonce_or_epoch(&order.maker_traits) >> 8,
                [0u8; 32],
            );
            snapshot.set_remaining_invalidator(order.maker, order_hash(batch, order), [0u8; 32]);
        }
        snapshot
    }
}

fn accumulate_word(map: &mut HashMap<AccountAsset, Word>, key: AccountAsset, amount: Word) {
    let current = map.entry(key).or_insert([0u8; 32]);
    *current = add_words(current, &amount).expect("synthetic snapshot amount overflow");
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RejectedTrade {
    pub index: usize,
    pub reason: RejectionReason,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum RejectionReason {
    MissingSnapshot(&'static str),
    Kyc(&'static str),
    InvalidSignature,
    InvalidMerkleProof,
    Expired,
    InvalidOrder,
    InvalidAmount,
    InvalidPrice,
    InvalidPrivateRecipient,
    BitInvalidated,
    DuplicateNonce,
    FifoViolation,
    InsufficientOrderRemaining,
    InsufficientBalance { owner: Address, token: Address },
    InsufficientAllowance { owner: Address, token: Address },
}

impl fmt::Display for RejectionReason {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::MissingSnapshot(kind) => write!(formatter, "missing {kind} snapshot"),
            Self::Kyc(role) => write!(formatter, "{role} KYC is not verified"),
            Self::InvalidSignature => formatter.write_str("invalid EIP-712 signature"),
            Self::InvalidMerkleProof => formatter.write_str("invalid KYC Merkle proof"),
            Self::Expired => formatter.write_str("order expired"),
            Self::InvalidOrder => formatter.write_str("order does not match the trade"),
            Self::InvalidAmount => formatter.write_str("invalid or overflowing amount"),
            Self::InvalidPrice => formatter.write_str("prices do not cross"),
            Self::InvalidPrivateRecipient => formatter.write_str("logical taker is not allowed"),
            Self::BitInvalidated => formatter.write_str("1inch bit invalidator is already set"),
            Self::DuplicateNonce => formatter.write_str("same 1inch bit invalidator is used twice"),
            Self::FifoViolation => formatter.write_str("FIFO_VIOLATION: Order executed out of order"),
            Self::InsufficientOrderRemaining => {
                formatter.write_str("order remaining amount is insufficient")
            }
            Self::InsufficientBalance { .. } => {
                formatter.write_str("insufficient cumulative balance")
            }
            Self::InsufficientAllowance { .. } => {
                formatter.write_str("insufficient cumulative allowance")
            }
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PreflightReport {
    pub clean_batch: BatchInput,
    pub rejected: Vec<RejectedTrade>,
    pub checked_trades: usize,
}

impl PreflightReport {
    pub fn should_prove(&self) -> bool {
        !self.clean_batch.trades.is_empty()
    }
}

#[derive(Debug, Error)]
pub enum PreflightError {
    #[error("batch snapshot RPC failed: {0}")]
    Rpc(String),
    #[error("multicall returned malformed data: {0}")]
    MalformedMulticall(String),
    #[error("multicall call {index} failed")]
    CallFailed { index: usize },
    #[error("batch is malformed: {0}")]
    InvalidBatch(&'static str),
    #[error("batch contains too many orders or trades")]
    BatchTooLarge,
}

#[async_trait]
pub trait SnapshotProvider: Send + Sync {
    async fn snapshot(&self, batch: &BatchInput) -> Result<BatchSnapshot, PreflightError>;
}

pub struct PreflightValidator<P> {
    provider: P,
}

impl<P> PreflightValidator<P>
where
    P: SnapshotProvider,
{
    pub fn new(provider: P) -> Self {
        Self { provider }
    }

    pub async fn validate_and_prune(
        &self,
        raw_batch: &BatchInput,
    ) -> Result<PreflightReport, PreflightError> {
        validate_batch_header(raw_batch)?;
        let snapshot = self.provider.snapshot(raw_batch).await?;
        let hashes =
            raw_batch.orders.iter().map(|order| order_hash(raw_batch, order)).collect::<Vec<_>>();
        if orderbook_root(&hashes) != raw_batch.orderbook_root {
            return Err(PreflightError::InvalidBatch("orderbook root mismatch"));
        }

        let mut consumed_assets: HashMap<AccountAsset, Word> = HashMap::new();
        let mut consumed_order_making: HashMap<usize, Word> = HashMap::new();
        let mut consumed_order_taking: HashMap<usize, Word> = HashMap::new();
        let mut reserved_bits: HashMap<(Address, u64), Word> = HashMap::new();
        let mut clean_trades = Vec::with_capacity(raw_batch.trades.len());
        let mut rejected = Vec::new();
        let mut validated_orders = HashSet::new();

        for (index, trade) in raw_batch.trades.iter().enumerate() {
            let result = validate_trade(
                raw_batch,
                trade,
                &hashes,
                &snapshot,
                &consumed_assets,
                &consumed_order_making,
                &consumed_order_taking,
                &reserved_bits,
                &mut validated_orders,
            );
            match result {
                Ok(()) => {
                    let seller_index = trade.maker_order_index as usize;
                    let buyer_index = trade.taker_order_index as usize;
                    add_consumed(
                        &mut consumed_assets,
                        AccountAsset { owner: trade.maker, token: trade.token_in },
                        trade.amount_in,
                    )?;
                    add_consumed(
                        &mut consumed_assets,
                        AccountAsset { owner: trade.taker, token: trade.token_out },
                        trade.amount_out,
                    )?;
                    add_consumed_order(&mut consumed_order_making, seller_index, trade.amount_in)?;
                    add_consumed_order(&mut consumed_order_making, buyer_index, trade.amount_out)?;
                    add_consumed_order(&mut consumed_order_taking, seller_index, trade.amount_out)?;
                    add_consumed_order(&mut consumed_order_taking, buyer_index, trade.amount_in)?;
                    reserve_bit(&mut reserved_bits, raw_batch, seller_index);
                    reserve_bit(&mut reserved_bits, raw_batch, buyer_index);
                    clean_trades.push(trade.clone());
                }
                Err(reason) => rejected.push(RejectedTrade { index, reason }),
            }
        }

        Ok(PreflightReport {
            clean_batch: BatchInput { trades: clean_trades, ..raw_batch.clone() },
            rejected,
            checked_trades: raw_batch.trades.len(),
        })
    }
}

fn validate_batch_header(batch: &BatchInput) -> Result<(), PreflightError> {
    if batch.chain_id != ARBITRUM_SEPOLIA_CHAIN_ID
        || batch.batch_timestamp == 0
        || batch.verifying_contract == [0u8; 20]
        || batch.limit_order_protocol == [0u8; 20]
        || batch.identity_registry == [0u8; 20]
        || batch.kyc_root == [0u8; 32]
        || batch.orderbook_root == [0u8; 32]
    {
        return Err(PreflightError::InvalidBatch("invalid header"));
    }
    if batch.orders.is_empty()
        || batch.orders.len() > MAX_ORDERS
        || batch.trades.is_empty()
        || batch.trades.len() > MAX_TRADES
    {
        return Err(PreflightError::BatchTooLarge);
    }
    if batch.trades.iter().any(|trade| {
        trade.maker_order_index as usize >= batch.orders.len()
            || trade.taker_order_index as usize >= batch.orders.len()
    }) {
        return Err(PreflightError::InvalidBatch("trade order index out of bounds"));
    }
    Ok(())
}

fn validate_trade(
    batch: &BatchInput,
    trade: &TradeSettlement,
    hashes: &[Word],
    snapshot: &BatchSnapshot,
    consumed_assets: &HashMap<AccountAsset, Word>,
    consumed_order_making: &HashMap<usize, Word>,
    consumed_order_taking: &HashMap<usize, Word>,
    reserved_bits: &HashMap<(Address, u64), Word>,
    validated_orders: &mut HashSet<usize>,
) -> Result<(), RejectionReason> {
    let seller_index = trade.maker_order_index as usize;
    let buyer_index = trade.taker_order_index as usize;
    if seller_index >= batch.orders.len()
        || buyer_index >= batch.orders.len()
        || seller_index == buyer_index
    {
        return Err(RejectionReason::InvalidOrder);
    }
    if !validated_orders.contains(&seller_index) {
        validate_order(batch, seller_index, &batch.orders[seller_index], &hashes[seller_index])?;
        validated_orders.insert(seller_index);
    }
    if !validated_orders.contains(&buyer_index) {
        validate_order(batch, buyer_index, &batch.orders[buyer_index], &hashes[buyer_index])?;
        validated_orders.insert(buyer_index);
    }

    let seller = &batch.orders[seller_index];
    let buyer = &batch.orders[buyer_index];
    if trade.maker != seller.maker
        || trade.taker != buyer.maker
        || trade.token_in != seller.maker_asset
        || trade.token_out != seller.taker_asset
        || buyer.maker_asset != trade.token_out
        || buyer.taker_asset != trade.token_in
        || trade.amount_in == [0u8; 32]
        || trade.amount_out == [0u8; 32]
    {
        return Err(RejectionReason::InvalidOrder);
    }
    check_allowed_sender(&seller.maker_traits, &trade.taker)?;
    check_allowed_sender(&buyer.maker_traits, &trade.maker)?;

    let amount_in = amount(&trade.amount_in);
    let amount_out = amount(&trade.amount_out);
    let seller_making = amount(&seller.making_amount);
    let seller_taking = amount(&seller.taking_amount);
    let buyer_making = amount(&buyer.making_amount);
    let buyer_taking = amount(&buyer.taking_amount);
    let seller_remaining_in = remaining(consumed_order_making, seller_index, seller_making);
    let seller_remaining_out = remaining(consumed_order_taking, seller_index, seller_taking);
    let buyer_remaining_out = remaining(consumed_order_making, buyer_index, buyer_making);
    let buyer_remaining_in = remaining(consumed_order_taking, buyer_index, buyer_taking);
    if amount_in > seller_remaining_in
        || amount_out > seller_remaining_out
        || amount_out > buyer_remaining_out
        || amount_in > buyer_remaining_in
    {
        return Err(RejectionReason::InsufficientOrderRemaining);
    }

    if product(seller_taking, buyer_taking) > product(buyer_making, seller_making)
        || get_taking_amount(seller_making, seller_taking, amount_in) != amount_out
        || get_taking_amount(buyer_making, buyer_taking, amount_out) != amount_in
    {
        return Err(RejectionReason::InvalidPrice);
    }
    if fifo_violation(batch, consumed_order_making, seller_index)
        || fifo_violation(batch, consumed_order_making, buyer_index)
    {
        return Err(RejectionReason::FifoViolation);
    }

    if !snapshot.verified.get(&trade.maker).copied().unwrap_or(false) {
        return Err(if snapshot.verified.contains_key(&trade.maker) {
            RejectionReason::Kyc("maker")
        } else {
            RejectionReason::MissingSnapshot("maker KYC")
        });
    }
    if !snapshot.verified.get(&trade.taker).copied().unwrap_or(false) {
        return Err(if snapshot.verified.contains_key(&trade.taker) {
            RejectionReason::Kyc("taker")
        } else {
            RejectionReason::MissingSnapshot("taker KYC")
        });
    }
    validate_order_state(
        batch,
        seller_index,
        &hashes[seller_index],
        amount_in,
        snapshot,
        consumed_order_making,
        reserved_bits,
    )?;
    validate_order_state(
        batch,
        buyer_index,
        &hashes[buyer_index],
        amount_out,
        snapshot,
        consumed_order_making,
        reserved_bits,
    )?;
    ensure_available(
        snapshot,
        consumed_assets,
        AccountAsset { owner: trade.maker, token: trade.token_in },
        amount_in,
    )?;
    ensure_available(
        snapshot,
        consumed_assets,
        AccountAsset { owner: trade.taker, token: trade.token_out },
        amount_out,
    )?;
    Ok(())
}

fn validate_order(
    batch: &BatchInput,
    _index: usize,
    order: &Order,
    hash: &Word,
) -> Result<(), RejectionReason> {
    if order.maker == [0u8; 20]
        || order.maker_asset == [0u8; 20]
        || order.taker_asset == [0u8; 20]
        || amount(&order.making_amount) == U256::ZERO
        || amount(&order.taking_amount) == U256::ZERO
    {
        return Err(RejectionReason::InvalidOrder);
    }
    let expiry = expiration(&order.maker_traits);
    if batch.batch_timestamp > expiry && expiry != 0 {
        return Err(RejectionReason::Expired);
    }
    if recover_maker(hash, &order.signature) != Some(order.maker) {
        return Err(RejectionReason::InvalidSignature);
    }
    let proof = batch
        .kyc_merkle_proofs
        .get(order.kyc_proof_index as usize)
        .ok_or(RejectionReason::InvalidMerkleProof)?;
    if proof.subject != order.maker || proof.siblings.len() > MAX_KYC_PROOF_DEPTH {
        return Err(RejectionReason::InvalidMerkleProof);
    }
    if verify_kyc(&batch.kyc_root, proof) {
        Ok(())
    } else {
        Err(RejectionReason::InvalidMerkleProof)
    }
}

fn validate_order_state(
    batch: &BatchInput,
    order_index: usize,
    hash: &Word,
    fill_amount: U256,
    snapshot: &BatchSnapshot,
    consumed_order_making: &HashMap<usize, Word>,
    reserved_bits: &HashMap<(Address, u64), Word>,
) -> Result<(), RejectionReason> {
    let order = &batch.orders[order_index];
    if uses_bit_invalidator(&order.maker_traits) {
        let nonce = nonce_or_epoch(&order.maker_traits);
        let slot = nonce >> 8;
        let invalidator = snapshot
            .bit_invalidators
            .get(&(order.maker, slot))
            .ok_or(RejectionReason::MissingSnapshot("bit invalidator"))?;
        let mask = bit_mask(nonce);
        if !is_zero_word(&and_words(invalidator, &mask)) {
            return Err(RejectionReason::BitInvalidated);
        }
        if reserved_bits
            .get(&(order.maker, slot))
            .map(|used| !is_zero_word(&and_words(used, &mask)))
            .unwrap_or(false)
        {
            return Err(RejectionReason::DuplicateNonce);
        }
    } else {
        let raw = snapshot
            .remaining_invalidators
            .get(&(order.maker, *hash))
            .ok_or(RejectionReason::MissingSnapshot("remaining invalidator"))?;
        let available =
            if is_zero_word(raw) { amount(&order.making_amount) } else { amount(&not_words(raw)) };
        let used = amount(consumed_order_making.get(&order_index).unwrap_or(&[0u8; 32]));
        if used
            .checked_add(&fill_amount)
            .into_option()
            .map(|total| total > available)
            .unwrap_or(true)
        {
            return Err(RejectionReason::InsufficientOrderRemaining);
        }
    }
    Ok(())
}

fn ensure_available(
    snapshot: &BatchSnapshot,
    consumed: &HashMap<AccountAsset, Word>,
    key: AccountAsset,
    requested: U256,
) -> Result<(), RejectionReason> {
    let state =
        snapshot.assets.get(&key).ok_or(RejectionReason::MissingSnapshot("balance/allowance"))?;
    let used = amount(consumed.get(&key).unwrap_or(&[0u8; 32]));
    let total = used.checked_add(&requested).into_option().ok_or(RejectionReason::InvalidAmount)?;
    if total > amount(&state.balance) {
        return Err(RejectionReason::InsufficientBalance { owner: key.owner, token: key.token });
    }
    if total > amount(&state.allowance) {
        return Err(RejectionReason::InsufficientAllowance { owner: key.owner, token: key.token });
    }
    Ok(())
}

fn add_consumed(
    consumed: &mut HashMap<AccountAsset, Word>,
    key: AccountAsset,
    requested: Word,
) -> Result<(), PreflightError> {
    let current = consumed.entry(key).or_insert([0u8; 32]);
    *current = add_words(current, &requested)
        .ok_or_else(|| PreflightError::InvalidBatch("cumulative amount overflow"))?;
    Ok(())
}

fn add_consumed_order(
    consumed: &mut HashMap<usize, Word>,
    index: usize,
    requested: Word,
) -> Result<(), PreflightError> {
    let current = consumed.entry(index).or_insert([0u8; 32]);
    *current = add_words(current, &requested)
        .ok_or_else(|| PreflightError::InvalidBatch("order amount overflow"))?;
    Ok(())
}

fn reserve_bit(reserved: &mut HashMap<(Address, u64), Word>, batch: &BatchInput, index: usize) {
    let order = &batch.orders[index];
    if !uses_bit_invalidator(&order.maker_traits) {
        return;
    }
    let nonce = nonce_or_epoch(&order.maker_traits);
    let entry = reserved.entry((order.maker, nonce >> 8)).or_insert([0u8; 32]);
    *entry = or_words(entry, &bit_mask(nonce));
}

fn add_words(left: &Word, right: &Word) -> Option<Word> {
    let mut output = [0u8; 32];
    let mut carry = 0u16;
    for index in (0..32).rev() {
        let sum = left[index] as u16 + right[index] as u16 + carry;
        output[index] = sum as u8;
        carry = sum >> 8;
    }
    (carry == 0).then_some(output)
}

fn remaining(consumed: &HashMap<usize, Word>, index: usize, total: U256) -> U256 {
    let used = amount(consumed.get(&index).unwrap_or(&[0u8; 32]));
    total.checked_sub(&used).into_option().unwrap_or(U256::ZERO)
}

fn same_price(left: &Order, right: &Order) -> bool {
    product(amount(&left.making_amount), amount(&right.taking_amount))
        == product(amount(&left.taking_amount), amount(&right.making_amount))
}

fn fifo_violation(
    batch: &BatchInput,
    consumed_order_making: &HashMap<usize, Word>,
    fill_index: usize,
) -> bool {
    let filled = &batch.orders[fill_index];
    for (index, other) in batch.orders.iter().enumerate() {
        if index == fill_index {
            continue;
        }
        if other.maker_asset != filled.maker_asset || other.taker_asset != filled.taker_asset {
            continue;
        }
        if !same_price(filled, other) {
            continue;
        }
        if other.arrival_timestamp < filled.arrival_timestamp
            && remaining(consumed_order_making, index, amount(&other.making_amount)) != U256::ZERO
        {
            return true;
        }
    }
    false
}

fn amount(word: &Word) -> U256 {
    U256::from_be_slice(word)
}

fn keccak256(bytes: &[u8]) -> Word {
    let mut hasher = Keccak::v256();
    hasher.update(bytes);
    let mut digest = [0u8; 32];
    hasher.finalize(&mut digest);
    digest
}

fn widen(value: U256) -> U512 {
    let mut bytes = [0u8; 64];
    bytes[32..].copy_from_slice(&value.to_be_bytes());
    U512::from_be_slice(&bytes)
}

fn product(left: U256, right: U256) -> U512 {
    left.mul(&right)
}

fn get_taking_amount(making: U256, taking: U256, fill_making: U256) -> U256 {
    let (mut quotient, remainder) =
        product(fill_making, taking).div_rem(&NonZero::new(widen(making)).unwrap());
    if remainder != U512::ZERO {
        quotient = quotient.checked_add(&U512::ONE).unwrap();
    }
    let bytes = quotient.to_be_bytes();
    U256::from_be_slice(&bytes[32..])
}

fn expiration(maker_traits: &Word) -> u64 {
    u64::from_be_bytes([
        0,
        0,
        0,
        maker_traits[17],
        maker_traits[18],
        maker_traits[19],
        maker_traits[20],
        maker_traits[21],
    ])
}

fn nonce_or_epoch(maker_traits: &Word) -> u64 {
    u64::from_be_bytes([
        0,
        0,
        0,
        maker_traits[12],
        maker_traits[13],
        maker_traits[14],
        maker_traits[15],
        maker_traits[16],
    ])
}

fn allow_partial_fills(maker_traits: &Word) -> bool {
    maker_traits[0] & 0x80 == 0
}

fn allow_multiple_fills(maker_traits: &Word) -> bool {
    maker_traits[0] & 0x40 != 0
}

fn uses_bit_invalidator(maker_traits: &Word) -> bool {
    !allow_partial_fills(maker_traits) || !allow_multiple_fills(maker_traits)
}

fn check_allowed_sender(maker_traits: &Word, taker: &Address) -> Result<(), RejectionReason> {
    let allowed = &maker_traits[22..32];
    if allowed.iter().any(|byte| *byte != 0) && allowed != &taker[10..20] {
        return Err(RejectionReason::InvalidPrivateRecipient);
    }
    Ok(())
}

pub fn order_hash(batch: &BatchInput, order: &Order) -> Word {
    let mut encoded = Vec::with_capacity(160);
    encoded.extend_from_slice(&keccak256(DOMAIN_TYPE));
    encoded.extend_from_slice(&keccak256(DOMAIN_NAME));
    encoded.extend_from_slice(&keccak256(DOMAIN_VERSION));
    encoded.extend_from_slice(&uint64_word(batch.chain_id));
    encoded.extend_from_slice(&address_word(&batch.limit_order_protocol));
    let domain = keccak256(&encoded);

    let mut order_encoded = Vec::with_capacity(288);
    order_encoded.extend_from_slice(&keccak256(ORDER_TYPE));
    order_encoded.extend_from_slice(&order.salt);
    order_encoded.extend_from_slice(&address_word(&order.maker));
    order_encoded.extend_from_slice(&address_word(&order.receiver));
    order_encoded.extend_from_slice(&address_word(&order.maker_asset));
    order_encoded.extend_from_slice(&address_word(&order.taker_asset));
    order_encoded.extend_from_slice(&order.making_amount);
    order_encoded.extend_from_slice(&order.taking_amount);
    order_encoded.extend_from_slice(&order.maker_traits);
    let struct_hash = keccak256(&order_encoded);
    let mut typed_data = Vec::with_capacity(66);
    typed_data.extend_from_slice(&[0x19, 0x01]);
    typed_data.extend_from_slice(&domain);
    typed_data.extend_from_slice(&struct_hash);
    keccak256(&typed_data)
}

fn recover_maker(order_digest: &Word, signature: &[u8]) -> Option<Address> {
    let mut signature_bytes = [0u8; 64];
    let recovery_byte = match signature.len() {
        65 => {
            signature_bytes.copy_from_slice(&signature[..64]);
            signature[64].saturating_sub(27)
        }
        64 => {
            signature_bytes[..32].copy_from_slice(&signature[..32]);
            signature_bytes[32..].copy_from_slice(&signature[32..]);
            let recovery = signature_bytes[32] >> 7;
            signature_bytes[32] &= 0x7f;
            recovery
        }
        _ => return None,
    };
    if recovery_byte > 1 {
        return None;
    }
    let signature = Signature::from_slice(&signature_bytes).ok()?;
    if signature.normalize_s().is_some() {
        return None;
    }
    let recovery_id = RecoveryId::from_byte(recovery_byte)?;
    let key = VerifyingKey::recover_from_prehash(order_digest, &signature, recovery_id).ok()?;
    let digest = keccak256(&key.to_encoded_point(false).as_bytes()[1..]);
    digest[12..].try_into().ok()
}

fn verify_kyc(root: &Word, proof: &KycProof) -> bool {
    let mut node = keccak256(&proof.subject);
    for sibling in &proof.siblings {
        let mut pair = [0u8; 64];
        if node <= *sibling {
            pair[..32].copy_from_slice(&node);
            pair[32..].copy_from_slice(sibling);
        } else {
            pair[..32].copy_from_slice(sibling);
            pair[32..].copy_from_slice(&node);
        }
        node = keccak256(&pair);
    }
    node == *root
}

pub fn orderbook_root(hashes: &[Word]) -> Word {
    if hashes.is_empty() {
        return [0u8; 32];
    }
    let mut level = hashes.to_vec();
    while level.len() > 1 {
        let mut next = Vec::with_capacity((level.len() + 1) / 2);
        let mut index = 0;
        while index < level.len() {
            let right = if index + 1 < level.len() { level[index + 1] } else { level[index] };
            next.push(sorted_pair_hash(level[index], right));
            index += 2;
        }
        level = next;
    }
    level[0]
}

fn sorted_pair_hash(left: Word, right: Word) -> Word {
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

fn bit_mask(nonce: u64) -> Word {
    let mut mask = [0u8; 32];
    mask[31 - ((nonce & 0xff) / 8) as usize] = 1u8 << ((nonce & 0xff) % 8);
    mask
}

fn not_words(word: &Word) -> Word {
    let mut output = [0u8; 32];
    for index in 0..32 {
        output[index] = !word[index];
    }
    output
}

fn and_words(left: &Word, right: &Word) -> Word {
    let mut output = [0u8; 32];
    for index in 0..32 {
        output[index] = left[index] & right[index];
    }
    output
}

fn or_words(left: &Word, right: &Word) -> Word {
    let mut output = [0u8; 32];
    for index in 0..32 {
        output[index] = left[index] | right[index];
    }
    output
}

fn is_zero_word(word: &Word) -> bool {
    word.iter().all(|byte| *byte == 0)
}

#[derive(Clone)]
pub struct Multicall3Provider {
    rpc_url: String,
    client: Client,
}

impl Multicall3Provider {
    pub fn new(rpc_url: impl Into<String>) -> Self {
        Self { rpc_url: rpc_url.into(), client: Client::new() }
    }

    pub fn from_env() -> Result<Self, PreflightError> {
        let rpc_url =
            env::var("PREFLIGHT_RPC_URL").or_else(|_| env::var("ETH_RPC_URL")).map_err(|_| {
                PreflightError::Rpc("PREFLIGHT_RPC_URL or ETH_RPC_URL is required".into())
            })?;
        Ok(Self::new(rpc_url))
    }
}

#[async_trait]
impl SnapshotProvider for Multicall3Provider {
    async fn snapshot(&self, batch: &BatchInput) -> Result<BatchSnapshot, PreflightError> {
        let mut calls = Vec::with_capacity(batch.trades.len() * 10);
        for trade in &batch.trades {
            let seller = &batch.orders[trade.maker_order_index as usize];
            let buyer = &batch.orders[trade.taker_order_index as usize];
            calls.push(CallSpec::verified(batch.identity_registry, trade.maker));
            calls.push(CallSpec::verified(batch.identity_registry, trade.taker));
            calls.push(CallSpec::balance_of(trade.token_in, trade.maker));
            calls.push(CallSpec::allowance(trade.token_in, trade.maker, batch.verifying_contract));
            calls.push(CallSpec::balance_of(trade.token_out, trade.taker));
            calls.push(CallSpec::allowance(trade.token_out, trade.taker, batch.verifying_contract));
            calls.push(CallSpec::bit_invalidator(
                batch.limit_order_protocol,
                seller.maker,
                nonce_or_epoch(&seller.maker_traits) >> 8,
            ));
            calls.push(CallSpec::raw_remaining(
                batch.limit_order_protocol,
                seller.maker,
                order_hash(batch, seller),
            ));
            calls.push(CallSpec::bit_invalidator(
                batch.limit_order_protocol,
                buyer.maker,
                nonce_or_epoch(&buyer.maker_traits) >> 8,
            ));
            calls.push(CallSpec::raw_remaining(
                batch.limit_order_protocol,
                buyer.maker,
                order_hash(batch, buyer),
            ));
        }

        let calldata = encode_aggregate3(&calls);
        let request = json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "eth_call",
            "params": [
                {"to": hex_address(&MULTICALL3_ADDRESS), "data": format!("0x{}", hex::encode(calldata))},
                "latest"
            ]
        });
        let response: RpcResponse = self
            .client
            .post(&self.rpc_url)
            .json(&request)
            .send()
            .await
            .map_err(|error| PreflightError::Rpc(error.to_string()))?
            .json()
            .await
            .map_err(|error| PreflightError::Rpc(error.to_string()))?;
        if let Some(error) = response.error {
            return Err(PreflightError::Rpc(error.to_string()));
        }
        let result = response
            .result
            .ok_or_else(|| PreflightError::Rpc("eth_call returned no result".into()))?;
        let results = decode_aggregate3(&result)?;
        if results.len() != calls.len() {
            return Err(PreflightError::MalformedMulticall("result count mismatch".into()));
        }

        let mut snapshot = BatchSnapshot::default();
        for (index, group) in results.chunks_exact(10).enumerate() {
            let trade = &batch.trades[index];
            let seller = &batch.orders[trade.maker_order_index as usize];
            let buyer = &batch.orders[trade.taker_order_index as usize];
            snapshot.set_verified(trade.maker, decode_bool(&group[0])?);
            snapshot.set_verified(trade.taker, decode_bool(&group[1])?);
            snapshot.set_asset(
                trade.maker,
                trade.token_in,
                decode_word(&group[2])?,
                decode_word(&group[3])?,
            );
            snapshot.set_asset(
                trade.taker,
                trade.token_out,
                decode_word(&group[4])?,
                decode_word(&group[5])?,
            );
            snapshot.set_bit_invalidator(
                seller.maker,
                nonce_or_epoch(&seller.maker_traits) >> 8,
                decode_word(&group[6])?,
            );
            snapshot.set_remaining_invalidator(
                seller.maker,
                order_hash(batch, seller),
                decode_word(&group[7])?,
            );
            snapshot.set_bit_invalidator(
                buyer.maker,
                nonce_or_epoch(&buyer.maker_traits) >> 8,
                decode_word(&group[8])?,
            );
            snapshot.set_remaining_invalidator(
                buyer.maker,
                order_hash(batch, buyer),
                decode_word(&group[9])?,
            );
        }
        Ok(snapshot)
    }
}

#[derive(Clone)]
struct CallSpec {
    target: Address,
    data: Vec<u8>,
}

impl CallSpec {
    fn verified(target: Address, user: Address) -> Self {
        Self { target, data: function_call("isVerified(address)", &[address_word(&user)]) }
    }

    fn balance_of(target: Address, owner: Address) -> Self {
        Self { target, data: function_call("balanceOf(address)", &[address_word(&owner)]) }
    }

    fn allowance(target: Address, owner: Address, spender: Address) -> Self {
        Self {
            target,
            data: function_call(
                "allowance(address,address)",
                &[address_word(&owner), address_word(&spender)],
            ),
        }
    }

    fn bit_invalidator(target: Address, maker: Address, slot: u64) -> Self {
        Self {
            target,
            data: function_call(
                "bitInvalidatorForOrder(address,uint256)",
                &[address_word(&maker), uint64_word(slot)],
            ),
        }
    }

    fn raw_remaining(target: Address, maker: Address, hash: Word) -> Self {
        Self {
            target,
            data: function_call(
                "rawRemainingInvalidatorForOrder(address,bytes32)",
                &[address_word(&maker), hash],
            ),
        }
    }
}

fn function_call(signature: &str, words: &[Word]) -> Vec<u8> {
    let mut output = Vec::with_capacity(4 + words.len() * 32);
    output.extend_from_slice(&keccak256(signature.as_bytes())[..4]);
    for word in words {
        output.extend_from_slice(word);
    }
    output
}

fn encode_aggregate3(calls: &[CallSpec]) -> Vec<u8> {
    let mut body = Vec::new();
    body.extend_from_slice(&uint64_word(calls.len() as u64));
    let mut tuples = Vec::new();
    let mut offsets = Vec::with_capacity(calls.len());
    for call in calls {
        offsets.push(tuples.len());
        tuples.extend_from_slice(&address_word(&call.target));
        tuples.extend_from_slice(&uint64_word(1));
        tuples.extend_from_slice(&uint64_word(96));
        tuples.extend_from_slice(&uint64_word(call.data.len() as u64));
        tuples.extend_from_slice(&call.data);
        tuples.resize((tuples.len() + 31) / 32 * 32, 0);
    }
    for offset in offsets {
        body.extend_from_slice(&uint64_word((calls.len() * 32 + offset) as u64));
    }
    body.extend_from_slice(&tuples);
    let mut output = Vec::with_capacity(4 + 32 + body.len());
    output.extend_from_slice(&keccak256(b"aggregate3((address,bool,bytes)[])")[..4]);
    output.extend_from_slice(&uint64_word(32));
    output.extend_from_slice(&body);
    output
}

#[derive(Deserialize)]
struct RpcResponse {
    result: Option<String>,
    error: Option<RpcError>,
}

#[derive(Deserialize)]
struct RpcError {
    code: i64,
    message: String,
}

impl fmt::Display for RpcError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{} ({})", self.message, self.code)
    }
}

fn decode_aggregate3(value: &str) -> Result<Vec<Vec<u8>>, PreflightError> {
    let bytes = hex::decode(value.strip_prefix("0x").unwrap_or(value))
        .map_err(|error| PreflightError::MalformedMulticall(error.to_string()))?;
    let array_offset = read_usize(&bytes, 0)?;
    let length = read_usize(&bytes, array_offset)?;
    let offsets_base = array_offset + 32;
    let mut results = Vec::with_capacity(length);
    for index in 0..length {
        let tuple_start = offsets_base + read_usize(&bytes, offsets_base + index * 32)?;
        let success = read_usize(&bytes, tuple_start)? != 0;
        let data_start = tuple_start + read_usize(&bytes, tuple_start + 32)?;
        let data_length = read_usize(&bytes, data_start)?;
        let start = data_start + 32;
        let end = start
            .checked_add(data_length)
            .ok_or_else(|| PreflightError::MalformedMulticall("return data overflow".into()))?;
        if end > bytes.len() {
            return Err(PreflightError::MalformedMulticall("return data out of bounds".into()));
        }
        if !success {
            return Err(PreflightError::CallFailed { index });
        }
        results.push(bytes[start..end].to_vec());
    }
    Ok(results)
}

fn read_usize(bytes: &[u8], offset: usize) -> Result<usize, PreflightError> {
    let end = offset
        .checked_add(32)
        .ok_or_else(|| PreflightError::MalformedMulticall("offset overflow".into()))?;
    if end > bytes.len() || bytes[offset..offset + 24].iter().any(|byte| *byte != 0) {
        return Err(PreflightError::MalformedMulticall("invalid ABI offset".into()));
    }
    let mut value = [0u8; 8];
    value.copy_from_slice(&bytes[offset + 24..end]);
    Ok(usize::from_be_bytes(value))
}

fn decode_word(bytes: &[u8]) -> Result<Word, PreflightError> {
    bytes.try_into().map_err(|_| PreflightError::MalformedMulticall("expected ABI word".into()))
}

fn decode_bool(bytes: &[u8]) -> Result<bool, PreflightError> {
    let word = decode_word(bytes)?;
    if word[..31].iter().any(|byte| *byte != 0) || word[31] > 1 {
        return Err(PreflightError::MalformedMulticall("invalid bool".into()));
    }
    Ok(word[31] == 1)
}

fn address_word(address: &Address) -> Word {
    let mut word = [0u8; 32];
    word[12..].copy_from_slice(address);
    word
}

fn uint64_word(value: u64) -> Word {
    let mut word = [0u8; 32];
    word[24..].copy_from_slice(&value.to_be_bytes());
    word
}

fn hex_address(address: &Address) -> String {
    format!("0x{}", hex::encode(address))
}

#[derive(Clone, Default)]
pub struct StaticSnapshotProvider {
    snapshot: Arc<BatchSnapshot>,
}

impl StaticSnapshotProvider {
    pub fn new(snapshot: BatchSnapshot) -> Self {
        Self { snapshot: Arc::new(snapshot) }
    }
}

#[async_trait]
impl SnapshotProvider for StaticSnapshotProvider {
    async fn snapshot(&self, _batch: &BatchInput) -> Result<BatchSnapshot, PreflightError> {
        Ok((*self.snapshot).clone())
    }
}
