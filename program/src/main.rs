#![no_main]

sp1_zkvm::entrypoint!(main);

use crypto_bigint::{CheckedAdd, Encoding, NonZero, U256, U512};
use k256::ecdsa::{RecoveryId, Signature, VerifyingKey};
use serde::{Deserialize, Serialize};
use tiny_keccak::{Hasher, Keccak};

const ARBITRUM_SEPOLIA_CHAIN_ID: u64 = 421614;
const MAX_KYC_PROOF_DEPTH: usize = 64;
const ORDER_TYPE: &[u8] = b"Order(uint256 salt,address maker,address receiver,address makerAsset,address takerAsset,uint256 makingAmount,uint256 takingAmount,uint256 makerTraits)";
const DOMAIN_TYPE: &[u8] =
    b"EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)";
const DOMAIN_NAME: &[u8] = b"1inch Limit Order Protocol";
const DOMAIN_VERSION: &[u8] = b"4";
const PHASE1_SIGNATURE_ERROR: &str = "Only EOA secp256k1 signatures supported in Phase 1";

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
pub struct ProofInput {
    pub chain_id: u64,
    pub router: [u8; 20],
    pub logical_taker: [u8; 20],
    pub tfund: [u8; 20],
    pub settlement_token: [u8; 20],
    pub kyc_root: [u8; 32],
    pub current_timestamp: u64,
    pub fill_making_amount: [u8; 32],
    pub order: Order,
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

fn hash_domain(input: &ProofInput) -> [u8; 32] {
    let mut encoded = Vec::with_capacity(160);
    encoded.extend_from_slice(&keccak256(DOMAIN_TYPE));
    encoded.extend_from_slice(&keccak256(DOMAIN_NAME));
    encoded.extend_from_slice(&keccak256(DOMAIN_VERSION));
    encoded.extend_from_slice(&uint64_word(input.chain_id));
    encoded.extend_from_slice(&address_word(&input.router));
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
        _ => panic!("Only EOA secp256k1 signatures supported in Phase 1"),
    };
    assert!(recovery_byte <= 1, "Only EOA secp256k1 signatures supported in Phase 1");
    let signature = Signature::from_slice(&signature_bytes)
        .unwrap_or_else(|_| panic!("Only EOA secp256k1 signatures supported in Phase 1"));
    if signature.normalize_s().is_some() {
        panic!("Only EOA secp256k1 signatures supported in Phase 1");
    }
    let recovery_id = RecoveryId::from_byte(recovery_byte)
        .unwrap_or_else(|| panic!("Only EOA secp256k1 signatures supported in Phase 1"));
    let verifying_key = VerifyingKey::recover_from_prehash(order_hash, &signature, recovery_id)
        .unwrap_or_else(|_| panic!("Only EOA secp256k1 signatures supported in Phase 1"));
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

/// Mirrors AmountCalculatorLib.getTakingAmount using a full-width intermediate.
fn get_taking_amount(
    order_making_amount: U256,
    order_taking_amount: U256,
    fill_making_amount: U256,
) -> U256 {
    assert!(order_making_amount != U256::ZERO, "division by zero");
    let (mut quotient, remainder) = fill_making_amount
        .mul(&order_taking_amount)
        .div_rem(&NonZero::new(widen(order_making_amount)).unwrap());
    if remainder != U512::ZERO {
        quotient = quotient.checked_add(&U512::ONE).expect("amount arithmetic overflow");
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

fn nonce_or_epoch(maker_traits: &[u8; 32]) -> U256 {
    // MakerTraitsLib stores nonceOrEpoch in bits 120..159 (five bytes).
    let mut word = [0u8; 32];
    word[27..32].copy_from_slice(&maker_traits[12..17]);
    U256::from_be_slice(&word)
}

fn check_allowed_sender(maker_traits: &[u8; 32], logical_taker: &[u8; 20]) {
    // 1inch MakerTraits uses the low 80 bits for allowedSender, not a full address.
    let allowed_sender = &maker_traits[22..32];
    if allowed_sender.iter().any(|byte| *byte != 0) {
        assert_eq!(
            allowed_sender,
            &logical_taker[10..20],
            "Taker is not the allowed private recipient"
        );
    }
}

fn matching_commitment(
    order_hash: &[u8; 32],
    logical_taker: &[u8; 20],
    fill_making_amount: U256,
    settlement_nonce: U256,
) -> [u8; 32] {
    // Keep this byte layout identical to abi.encodePacked(bytes32,address,uint256,uint256).
    let mut encoded = Vec::with_capacity(32 + 20 + 32 + 32);
    encoded.extend_from_slice(order_hash);
    encoded.extend_from_slice(logical_taker);
    encoded.extend_from_slice(&fill_making_amount.to_be_bytes());
    encoded.extend_from_slice(&settlement_nonce.to_be_bytes());
    keccak256(&encoded)
}

fn public_values(
    input: &ProofInput,
    order_hash: &[u8; 32],
    fill_making_amount: U256,
    fill_taking_amount: U256,
    settlement_nonce: U256,
    commitment: &[u8; 32],
) -> Vec<u8> {
    let order = &input.order;
    let mut output = Vec::with_capacity(13 * 32);
    output.extend_from_slice(&uint64_word(input.chain_id));
    output.extend_from_slice(&address_word(&input.router));
    output.extend_from_slice(order_hash);
    output.extend_from_slice(&address_word(&order.maker));
    output.extend_from_slice(&address_word(&input.logical_taker));
    output.extend_from_slice(&address_word(&order.maker_asset));
    output.extend_from_slice(&address_word(&order.taker_asset));
    output.extend_from_slice(&order.making_amount);
    output.extend_from_slice(&order.taking_amount);
    output.extend_from_slice(&fill_making_amount.to_be_bytes());
    output.extend_from_slice(&fill_taking_amount.to_be_bytes());
    output.extend_from_slice(&settlement_nonce.to_be_bytes());
    output.extend_from_slice(commitment);
    output
}

pub fn main() {
    let input: ProofInput = sp1_zkvm::io::read();
    assert_eq!(input.chain_id, ARBITRUM_SEPOLIA_CHAIN_ID, "wrong chain");
    assert!(input.router != [0u8; 20], "zero router address");
    assert!(input.logical_taker != [0u8; 20], "zero logical taker");
    assert!(input.tfund != [0u8; 20], "zero TFUND address");
    assert!(input.settlement_token != [0u8; 20], "zero settlement token address");
    assert!(input.kyc_root != [0u8; 32], "zero KYC root");

    let order = &input.order;
    assert!(order.maker != [0u8; 20], "zero maker");
    assert!(order.maker_asset == input.tfund, "wrong maker asset");
    assert!(order.taker_asset == input.settlement_token, "wrong taker asset");
    assert!(amount(&order.making_amount) != U256::ZERO, "zero making amount");
    assert!(amount(&order.taking_amount) != U256::ZERO, "zero taking amount");

    check_allowed_sender(&order.maker_traits, &input.logical_taker);

    let fill_making_amount = amount(&input.fill_making_amount);
    assert!(fill_making_amount != U256::ZERO, "zero fill making amount");
    assert!(fill_making_amount <= amount(&order.making_amount), "fill exceeds order making amount");
    if order.maker_traits[0] & 0x80 != 0 {
        assert_eq!(fill_making_amount, amount(&order.making_amount), "partial fill is disabled");
    }

    let expiry = expiration(&order.maker_traits);
    if input.current_timestamp != 0 && expiry != 0 {
        assert!(input.current_timestamp <= expiry, "order expired");
    }

    let domain_separator = hash_domain(&input);
    let order_hash = hash_order(order, &domain_separator);
    assert_eq!(
        recover_maker(&order_hash, &order.signature),
        order.maker,
        "{}",
        PHASE1_SIGNATURE_ERROR
    );
    assert!(order.kyc_proof.len() <= MAX_KYC_PROOF_DEPTH, "KYC Merkle proof is too deep");
    verify_kyc(&input.kyc_root, &order.maker, &order.kyc_proof);

    let fill_taking_amount = get_taking_amount(
        amount(&order.making_amount),
        amount(&order.taking_amount),
        fill_making_amount,
    );
    assert!(fill_taking_amount != U256::ZERO, "zero fill taking amount");
    assert!(fill_taking_amount <= amount(&order.taking_amount), "fill exceeds order taking amount");

    // nonceOrEpoch is part of the signed makerTraits, so it cannot be chosen
    // independently for a replay with a different matching commitment.
    let settlement_nonce = nonce_or_epoch(&order.maker_traits);
    let commitment = matching_commitment(
        &order_hash,
        &input.logical_taker,
        fill_making_amount,
        settlement_nonce,
    );
    sp1_zkvm::io::commit_slice(&public_values(
        &input,
        &order_hash,
        fill_making_amount,
        fill_taking_amount,
        settlement_nonce,
        &commitment,
    ));
}
