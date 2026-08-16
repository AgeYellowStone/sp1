#![no_main]

sp1_zkvm::entrypoint!(main);

use crypto_bigint::{Encoding, NonZero, U256, U512};
use k256::ecdsa::{RecoveryId, Signature, VerifyingKey};
use serde::{Deserialize, Serialize};
use tiny_keccak::{Hasher, Keccak};

const MAX_ORDERS: usize = 64;
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
    pub kyc_proof: Vec<[u8; 32]>,
}

#[derive(Clone, Serialize, Deserialize)]
pub struct BatchInput {
    pub chain_id: u64,
    pub verifying_contract: [u8; 20],
    pub tfund: [u8; 20],
    pub usdc: [u8; 20],
    pub identity_registry: [u8; 20],
    pub kyc_root: [u8; 32],
    pub current_timestamp: u64,
    pub orders: Vec<Order>,
}

#[derive(Clone, Copy)]
struct Trade {
    seller_index: u32,
    buyer_index: u32,
    tfund_amount: U256,
    usdc_amount: U256,
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
    let domain_type_hash = keccak256(DOMAIN_TYPE);
    let name_hash = keccak256(DOMAIN_NAME);
    let version_hash = keccak256(DOMAIN_VERSION);
    let mut encoded = Vec::with_capacity(160);
    encoded.extend_from_slice(&domain_type_hash);
    encoded.extend_from_slice(&name_hash);
    encoded.extend_from_slice(&version_hash);
    encoded.extend_from_slice(&uint64_word(input.chain_id));
    encoded.extend_from_slice(&address_word(&input.verifying_contract));
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
        _ => panic!("signature must be 64 or 65 bytes"),
    };
    assert!(recovery_byte <= 1, "invalid Ethereum recovery id");
    let signature = Signature::from_slice(&signature_bytes).unwrap();
    let recovery_id = RecoveryId::from_byte(recovery_byte).unwrap();
    let verifying_key =
        VerifyingKey::recover_from_prehash(order_hash, &signature, recovery_id).unwrap();
    let encoded_key = verifying_key.to_encoded_point(false);
    let digest = keccak256(&encoded_key.as_bytes()[1..]);
    digest[12..].try_into().unwrap()
}

fn verify_kyc(root: &[u8; 32], address: &[u8; 20], proof: &[[u8; 32]]) {
    let mut node = keccak256(address);
    for sibling in proof {
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

fn amount_word(value: U256) -> [u8; 32] {
    value.to_be_bytes()
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

fn floor_ratio(numerator: U256, multiplier: U256, denominator: U256) -> Option<U256> {
    assert!(denominator != U256::ZERO, "division by zero");
    let (quotient, _) =
        product(numerator, multiplier).div_rem(&NonZero::new(widen(denominator)).unwrap());
    narrow(quotient)
}

fn ceil_ratio(numerator: U256, multiplier: U256, denominator: U256) -> Option<U256> {
    assert!(denominator != U256::ZERO, "division by zero");
    let (mut quotient, remainder) =
        product(numerator, multiplier).div_rem(&NonZero::new(widen(denominator)).unwrap());
    if remainder != U512::ZERO {
        quotient = quotient + U512::ONE;
    }
    narrow(quotient)
}

fn min_amount(left: U256, right: U256) -> U256 {
    if left < right {
        left
    } else {
        right
    }
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

fn build_trades(input: &BatchInput, orders: &[Order]) -> Vec<Trade> {
    let order_count = orders.len();
    let mut remaining_maker =
        orders.iter().map(|order| amount(&order.making_amount)).collect::<Vec<_>>();
    let mut remaining_taker =
        orders.iter().map(|order| amount(&order.taking_amount)).collect::<Vec<_>>();
    let mut trades = Vec::new();

    for seller_index in 0..order_count {
        let seller = &orders[seller_index];
        if seller.maker_asset != input.tfund || seller.taker_asset != input.usdc {
            continue;
        }
        let seller_making = amount(&seller.making_amount);
        let seller_taking = amount(&seller.taking_amount);
        assert!(seller_making > U256::ZERO && seller_taking > U256::ZERO);

        for buyer_index in 0..order_count {
            let buyer = &orders[buyer_index];
            if buyer.maker_asset != input.usdc
                || buyer.taker_asset != input.tfund
                || seller_index == buyer_index
            {
                continue;
            }
            let buyer_making = amount(&buyer.making_amount);
            let buyer_taking = amount(&buyer.taking_amount);
            if buyer_making == U256::ZERO
                || buyer_taking == U256::ZERO
                || remaining_maker[seller_index] == U256::ZERO
                || remaining_taker[buyer_index] == U256::ZERO
            {
                continue;
            }

            // Seller ask <= buyer bid. All arithmetic is checked before entering the proof.
            let ask_value = product(seller_taking, buyer_taking);
            let bid_value = product(buyer_making, seller_making);
            if ask_value > bid_value {
                continue;
            }

            let Some(seller_tfund_capacity) =
                floor_ratio(remaining_taker[seller_index], seller_making, seller_taking)
            else {
                continue;
            };
            let Some(buyer_tfund_capacity) =
                floor_ratio(remaining_maker[buyer_index], buyer_taking, buyer_making)
            else {
                continue;
            };
            let tfund_amount = min_amount(
                min_amount(remaining_maker[seller_index], remaining_taker[buyer_index]),
                min_amount(seller_tfund_capacity, buyer_tfund_capacity),
            );
            if tfund_amount == U256::ZERO {
                continue;
            }

            let Some(usdc_amount) = ceil_ratio(tfund_amount, seller_taking, seller_making) else {
                continue;
            };
            if usdc_amount == U256::ZERO
                || usdc_amount > remaining_maker[buyer_index]
                || usdc_amount > remaining_taker[seller_index]
            {
                continue;
            }

            remaining_maker[seller_index] =
                remaining_maker[seller_index].wrapping_sub(&tfund_amount);
            remaining_taker[seller_index] =
                remaining_taker[seller_index].wrapping_sub(&usdc_amount);
            remaining_taker[buyer_index] = remaining_taker[buyer_index].wrapping_sub(&tfund_amount);
            remaining_maker[buyer_index] = remaining_maker[buyer_index].wrapping_sub(&usdc_amount);
            trades.push(Trade {
                seller_index: seller_index as u32,
                buyer_index: buyer_index as u32,
                tfund_amount,
                usdc_amount,
            });
        }
    }
    trades
}

fn public_values(
    input: &BatchInput,
    hashes: &[[u8; 32]],
    trades: &[Trade],
    domain_separator: &[u8; 32],
) -> Vec<u8> {
    let mut output = Vec::with_capacity(256 + trades.len() * 72);
    output.extend_from_slice(b"RWA1");
    output.extend_from_slice(&input.chain_id.to_be_bytes());
    output.extend_from_slice(&input.current_timestamp.to_be_bytes());
    output.extend_from_slice(&input.verifying_contract);
    output.extend_from_slice(&input.tfund);
    output.extend_from_slice(&input.usdc);
    output.extend_from_slice(&input.identity_registry);
    output.extend_from_slice(domain_separator);
    output.extend_from_slice(&input.kyc_root);
    output.extend_from_slice(&orderbook_root(hashes));
    output.extend_from_slice(&(hashes.len() as u32).to_be_bytes());
    output.extend_from_slice(&(trades.len() as u32).to_be_bytes());
    for trade in trades {
        output.extend_from_slice(&trade.seller_index.to_be_bytes());
        output.extend_from_slice(&trade.buyer_index.to_be_bytes());
        output.extend_from_slice(&amount_word(trade.tfund_amount));
        output.extend_from_slice(&amount_word(trade.usdc_amount));
    }
    output
}

pub fn main() {
    let input: BatchInput = sp1_zkvm::io::read();
    assert!(
        !input.orders.is_empty() && input.orders.len() <= MAX_ORDERS,
        "invalid order batch size"
    );
    assert!(input.tfund != [0u8; 20], "zero TFUND address");
    assert!(input.usdc != [0u8; 20], "zero settlement asset address");
    assert!(input.identity_registry != [0u8; 20], "zero IdentityRegistry address");
    assert!(input.kyc_root != [0u8; 32], "zero KYC root");

    let domain_separator = hash_domain(&input);
    let mut order_hashes = Vec::with_capacity(input.orders.len());
    for order in &input.orders {
        assert!(order.maker != [0u8; 20], "zero maker");
        assert!(
            (order.maker_asset == input.tfund && order.taker_asset == input.usdc)
                || (order.maker_asset == input.usdc && order.taker_asset == input.tfund),
            "unsupported asset pair"
        );
        let expiry = expiration(&order.maker_traits);
        if input.current_timestamp != 0 && expiry != 0 {
            assert!(input.current_timestamp <= expiry, "order expired");
        }
        let order_hash = hash_order(order, &domain_separator);
        assert_eq!(
            recover_maker(&order_hash, &order.signature),
            order.maker,
            "invalid EIP-712 signature"
        );
        assert!(order.kyc_proof.len() <= MAX_KYC_PROOF_DEPTH, "KYC Merkle proof is too deep");
        verify_kyc(&input.kyc_root, &order.maker, &order.kyc_proof);
        order_hashes.push(order_hash);
    }

    let trades = build_trades(&input, &input.orders);
    assert!(!trades.is_empty(), "order batch has no crossing prices");
    sp1_zkvm::io::commit_slice(&public_values(&input, &order_hashes, &trades, &domain_separator));
}
