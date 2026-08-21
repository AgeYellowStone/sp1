#![no_main]

sp1_zkvm::entrypoint!(main);

mod codec;

use crypto_bigint::{CheckedAdd, Encoding, NonZero, U256, U512};
use k256::ecdsa::{RecoveryId, Signature, VerifyingKey};
use serde::{Deserialize, Serialize};
use tiny_keccak::{Hasher, Keccak};

const ARBITRUM_SEPOLIA_CHAIN_ID: u64 = 421614;
const MAX_ORDERS: usize = 128;
const MAX_TRADES: usize = 256;
const MAX_KYC_PROOF_DEPTH: usize = 64;
const ORDER_TYPE: &[u8] = b"Order(uint256 salt,address maker,address receiver,address makerAsset,address takerAsset,uint256 makingAmount,uint256 takingAmount,uint256 makerTraits)";
const DOMAIN_TYPE: &[u8] =
    b"EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)";
const DOMAIN_NAME: &[u8] = b"1inch Limit Order Protocol";
const DOMAIN_VERSION: &[u8] = b"4";

#[derive(Clone, Serialize, Deserialize)]
pub struct Order {
    pub salt: [u8; 32],
    pub maker: [u8; 20],
    pub receiver: [u8; 20],
    pub maker_asset: [u8; 20],
    pub taker_asset: [u8; 20],
    pub making_amount: [u8; 32],
    pub taking_amount: [u8; 32],
    pub maker_traits: [u8; 32],
    pub signature: Vec<u8>,
    pub kyc_proof_index: u32,
    #[serde(default)]
    pub arrival_timestamp: u64,
}

#[derive(Clone, Serialize, Deserialize)]
pub struct KycProof {
    pub subject: [u8; 20],
    pub siblings: Vec<[u8; 32]>,
}

#[derive(Clone, Serialize, Deserialize)]
pub struct TradeSettlement {
    pub maker: [u8; 20],
    pub taker: [u8; 20],
    pub token_in: [u8; 20],
    pub token_out: [u8; 20],
    pub amount_in: [u8; 32],
    pub amount_out: [u8; 32],
    pub maker_order_index: u32,
    pub taker_order_index: u32,
}

#[derive(Clone, Serialize, Deserialize)]
pub struct BatchInput {
    pub chain_id: u64,
    pub batch_timestamp: u64,
    pub verifying_contract: [u8; 20],
    pub limit_order_protocol: [u8; 20],
    pub identity_registry: [u8; 20],
    pub kyc_root: [u8; 32],
    pub orderbook_root: [u8; 32],
    pub orders: Vec<Order>,
    pub trades: Vec<TradeSettlement>,
    pub kyc_merkle_proofs: Vec<KycProof>,
}

fn keccak256(bytes: &[u8]) -> [u8; 32] {
    let mut hasher = Keccak::v256();
    hasher.update(bytes);
    let mut digest = [0u8; 32];
    hasher.finalize(&mut digest);
    digest
}

fn address_word(address: &[u8; 20]) -> [u8; 32] {
    let mut word = [0u8; 32];
    word[12..].copy_from_slice(address);
    word
}

fn uint64_word(value: u64) -> [u8; 32] {
    let mut word = [0u8; 32];
    word[24..].copy_from_slice(&value.to_be_bytes());
    word
}

fn hash_domain(input: &BatchInput) -> [u8; 32] {
    let mut encoded = Vec::with_capacity(160);
    encoded.extend_from_slice(&keccak256(DOMAIN_TYPE));
    encoded.extend_from_slice(&keccak256(DOMAIN_NAME));
    encoded.extend_from_slice(&keccak256(DOMAIN_VERSION));
    encoded.extend_from_slice(&uint64_word(input.chain_id));
    encoded.extend_from_slice(&address_word(&input.limit_order_protocol));
    keccak256(&encoded)
}

fn hash_order(order: &Order, domain_separator: &[u8; 32]) -> [u8; 32] {
    let mut encoded = Vec::with_capacity(288);
    encoded.extend_from_slice(&keccak256(ORDER_TYPE));
    encoded.extend_from_slice(&order.salt);
    encoded.extend_from_slice(&address_word(&order.maker));
    encoded.extend_from_slice(&address_word(&order.receiver));
    encoded.extend_from_slice(&address_word(&order.maker_asset));
    encoded.extend_from_slice(&address_word(&order.taker_asset));
    encoded.extend_from_slice(&order.making_amount);
    encoded.extend_from_slice(&order.taking_amount);
    encoded.extend_from_slice(&order.maker_traits);
    let struct_hash = keccak256(&encoded);

    let mut typed_data = Vec::with_capacity(66);
    typed_data.extend_from_slice(&[0x19, 0x01]);
    typed_data.extend_from_slice(domain_separator);
    typed_data.extend_from_slice(&struct_hash);
    keccak256(&typed_data)
}

fn recover_maker(order_hash: &[u8; 32], signature: &[u8]) -> [u8; 20] {
    let mut signature_bytes = [0u8; 64];
    let recovery_byte = match signature.len() {
        65 => {
            signature_bytes.copy_from_slice(&signature[..64]);
            let mut recovery_byte = signature[64];
            if recovery_byte >= 27 {
                recovery_byte -= 27;
            }
            recovery_byte
        }
        64 => {
            signature_bytes[..32].copy_from_slice(&signature[..32]);
            signature_bytes[32..].copy_from_slice(&signature[32..]);
            let recovery_byte = signature_bytes[32] >> 7;
            signature_bytes[32] &= 0x7f;
            recovery_byte
        }
        _ => panic!("invalid EOA signature length"),
    };
    assert!(recovery_byte <= 1, "invalid Ethereum recovery id");
    let signature = Signature::from_slice(&signature_bytes).expect("invalid ECDSA signature");
    assert!(signature.normalize_s().is_none(), "high-s ECDSA signature");
    let recovery_id = RecoveryId::from_byte(recovery_byte).expect("invalid recovery id");
    let verifying_key = VerifyingKey::recover_from_prehash(order_hash, &signature, recovery_id)
        .expect("bad signature");
    let encoded_key = verifying_key.to_encoded_point(false);
    let digest = keccak256(&encoded_key.as_bytes()[1..]);
    digest[12..].try_into().unwrap()
}

fn verify_kyc(root: &[u8; 32], proof: &KycProof) {
    assert!(proof.siblings.len() <= MAX_KYC_PROOF_DEPTH, "KYC proof is too deep");
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
    assert_eq!(node, *root, "KYC Merkle proof is invalid");
}

fn amount(word: &[u8; 32]) -> U256 {
    U256::from_be_slice(word)
}

fn widen(value: U256) -> U512 {
    let mut bytes = [0u8; 64];
    bytes[32..].copy_from_slice(&value.to_be_bytes());
    U512::from_be_slice(&bytes)
}

fn narrow(value: U512) -> Option<U256> {
    if value > widen(U256::MAX) {
        return None;
    }
    let bytes = value.to_be_bytes();
    Some(U256::from_be_slice(&bytes[32..]))
}

fn product(left: U256, right: U256) -> U512 {
    left.mul(&right)
}

fn get_taking_amount(making: U256, taking: U256, fill_making: U256) -> U256 {
    assert!(making != U256::ZERO, "division by zero");
    let (mut quotient, remainder) =
        product(fill_making, taking).div_rem(&NonZero::new(widen(making)).unwrap());
    if remainder != U512::ZERO {
        quotient = quotient.checked_add(&U512::ONE).expect("amount overflow");
    }
    narrow(quotient).expect("amount overflow")
}

fn expiration(maker_traits: &[u8; 32]) -> u64 {
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

fn check_allowed_sender(maker_traits: &[u8; 32], logical_taker: &[u8; 20]) {
    let allowed_sender = &maker_traits[22..32];
    if allowed_sender.iter().any(|byte| *byte != 0) {
        assert_eq!(allowed_sender, &logical_taker[10..20], "taker is not allowed");
    }
}

fn sorted_pair_hash(left: [u8; 32], right: [u8; 32]) -> [u8; 32] {
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

fn orderbook_root(hashes: &[[u8; 32]]) -> [u8; 32] {
    assert!(!hashes.is_empty(), "empty orderbook");
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

fn same_price(left: &Order, right: &Order) -> bool {
    product(amount(&left.making_amount), amount(&right.taking_amount))
        == product(amount(&left.taking_amount), amount(&right.making_amount))
}

fn assert_fifo(orders: &[Order], remaining_making: &[U256], fill_index: usize) {
    let filled = &orders[fill_index];
    for (index, other) in orders.iter().enumerate() {
        if index == fill_index {
            continue;
        }
        if other.maker_asset != filled.maker_asset || other.taker_asset != filled.taker_asset {
            continue;
        }
        if !same_price(filled, other) {
            continue;
        }
        if other.arrival_timestamp < filled.arrival_timestamp && remaining_making[index] != U256::ZERO
        {
            panic!("FIFO_VIOLATION: Order executed out of order");
        }
    }
}

fn validate_order(input: &BatchInput, order: &Order, order_hash: &[u8; 32]) {
    assert!(order.maker != [0u8; 20], "zero maker");
    assert!(order.maker_asset != [0u8; 20], "zero maker asset");
    assert!(order.taker_asset != [0u8; 20], "zero taker asset");
    assert!(amount(&order.making_amount) != U256::ZERO, "zero making amount");
    assert!(amount(&order.taking_amount) != U256::ZERO, "zero taking amount");
    let expiry = expiration(&order.maker_traits);
    if input.batch_timestamp != 0 && expiry != 0 {
        assert!(input.batch_timestamp <= expiry, "order expired");
    }
    assert_eq!(recover_maker(order_hash, &order.signature), order.maker, "invalid order signature");
    let proof =
        input.kyc_merkle_proofs.get(order.kyc_proof_index as usize).expect("missing KYC proof");
    assert_eq!(proof.subject, order.maker, "KYC proof subject mismatch");
    verify_kyc(&input.kyc_root, proof);
}

pub fn main() {
    let input: BatchInput = sp1_zkvm::io::read();
    assert_eq!(input.chain_id, ARBITRUM_SEPOLIA_CHAIN_ID, "wrong chain");
    assert!(input.orders.len() > 0 && input.orders.len() <= MAX_ORDERS, "invalid order count");
    assert!(input.trades.len() > 0 && input.trades.len() <= MAX_TRADES, "invalid trade count");
    assert!(input.verifying_contract != [0u8; 20], "zero settlement contract");
    assert!(input.limit_order_protocol != [0u8; 20], "zero 1inch protocol");
    assert!(input.identity_registry != [0u8; 20], "zero identity registry");
    assert!(input.kyc_root != [0u8; 32], "zero KYC root");
    assert!(input.orderbook_root != [0u8; 32], "zero orderbook root");

    let domain_separator = hash_domain(&input);
    let order_hashes =
        input.orders.iter().map(|order| hash_order(order, &domain_separator)).collect::<Vec<_>>();
    assert_eq!(orderbook_root(&order_hashes), input.orderbook_root, "orderbook root mismatch");

    let mut referenced = vec![false; input.orders.len()];
    for trade in &input.trades {
        let maker_index = trade.maker_order_index as usize;
        let taker_index = trade.taker_order_index as usize;
        assert!(
            maker_index < input.orders.len() && taker_index < input.orders.len(),
            "order index out of bounds"
        );
        assert!(maker_index != taker_index, "trade uses one order twice");
        referenced[maker_index] = true;
        referenced[taker_index] = true;
    }
    for (index, order) in input.orders.iter().enumerate() {
        if referenced[index] {
            validate_order(&input, order, &order_hashes[index]);
        }
    }

    let mut remaining_making =
        input.orders.iter().map(|order| amount(&order.making_amount)).collect::<Vec<_>>();
    let mut remaining_taking =
        input.orders.iter().map(|order| amount(&order.taking_amount)).collect::<Vec<_>>();

    for trade in &input.trades {
        let seller_index = trade.maker_order_index as usize;
        let buyer_index = trade.taker_order_index as usize;
        let seller = &input.orders[seller_index];
        let buyer = &input.orders[buyer_index];
        let amount_in = amount(&trade.amount_in);
        let amount_out = amount(&trade.amount_out);
        assert!(amount_in != U256::ZERO && amount_out != U256::ZERO, "zero trade amount");
        assert_eq!(trade.maker, seller.maker, "maker binding mismatch");
        assert_eq!(trade.taker, buyer.maker, "taker binding mismatch");
        assert_eq!(trade.token_in, seller.maker_asset, "seller token binding mismatch");
        assert_eq!(trade.token_out, seller.taker_asset, "seller token pair mismatch");
        assert_eq!(buyer.maker_asset, trade.token_out, "buyer token pair mismatch");
        assert_eq!(buyer.taker_asset, trade.token_in, "buyer token pair mismatch");
        check_allowed_sender(&seller.maker_traits, &trade.taker);
        check_allowed_sender(&buyer.maker_traits, &trade.maker);

        assert!(amount_in <= remaining_making[seller_index], "seller overfilled");
        assert!(amount_out <= remaining_taking[seller_index], "seller taking overfilled");
        assert!(amount_out <= remaining_making[buyer_index], "buyer overfilled");
        assert!(amount_in <= remaining_taking[buyer_index], "buyer taking overfilled");

        let ask_value = product(amount(&seller.taking_amount), amount(&buyer.taking_amount));
        let bid_value = product(amount(&buyer.making_amount), amount(&seller.making_amount));
        assert!(ask_value <= bid_value, "prices do not cross");
        assert_eq!(
            get_taking_amount(
                amount(&seller.making_amount),
                amount(&seller.taking_amount),
                amount_in
            ),
            amount_out,
            "seller amount mismatch"
        );
        assert_eq!(
            get_taking_amount(
                amount(&buyer.making_amount),
                amount(&buyer.taking_amount),
                amount_out
            ),
            amount_in,
            "buyer amount mismatch"
        );

        assert_fifo(&input.orders, &remaining_making, seller_index);
        assert_fifo(&input.orders, &remaining_making, buyer_index);

        remaining_making[seller_index] = remaining_making[seller_index].wrapping_sub(&amount_in);
        remaining_taking[seller_index] = remaining_taking[seller_index].wrapping_sub(&amount_out);
        remaining_making[buyer_index] = remaining_making[buyer_index].wrapping_sub(&amount_out);
        remaining_taking[buyer_index] = remaining_taking[buyer_index].wrapping_sub(&amount_in);
    }

    let public_values = codec::encode_public_values(&input);
    assert_eq!(public_values.len(), codec::PUBLIC_VALUES_LEN, "public values length mismatch");
    sp1_zkvm::io::commit_slice(&public_values);
}
