use std::{env, fs, path::PathBuf, time::Instant};

use k256::ecdsa::{signature::hazmat::PrehashSigner, SigningKey};
use serde::{Deserialize, Serialize};
use sp1_sdk::{include_elf, HashableKey, ProveRequest, Prover, ProverClient, ProvingKey, SP1Stdin};
use tiny_keccak::{Hasher, Keccak};

const ELF: sp1_sdk::Elf = include_elf!("rwa-dex-batch-program");
const CHAIN_ID: u64 = 421614;
const TFUND: [u8; 20] = hex_bytes("4f955D0B96C20e88E5da6f632057e0BfA62c871e");
const USDC: [u8; 20] = hex_bytes("17B9002eaeAeD3734C357C9662DEA5DD49aAA2cE");
const EXTENSION: [u8; 20] = hex_bytes("ed281B3a066A5818FE119E33fb1e1719185a8a25");

const fn hex_nibble(value: u8) -> u8 {
    match value {
        b'0'..=b'9' => value - b'0',
        b'a'..=b'f' => value - b'a' + 10,
        b'A'..=b'F' => value - b'A' + 10,
        _ => panic!("invalid hex literal"),
    }
}

const fn hex_bytes<const N: usize>(value: &str) -> [u8; N] {
    let bytes = value.as_bytes();
    assert!(bytes.len() == N * 2);
    let mut output = [0u8; N];
    let mut index = 0;
    while index < N {
        output[index] = (hex_nibble(bytes[index * 2]) << 4) | hex_nibble(bytes[index * 2 + 1]);
        index += 1;
    }
    output
}

#[derive(Clone, Serialize, Deserialize)]
struct Order {
    salt: [u8; 32],
    maker: [u8; 20],
    receiver: [u8; 20],
    maker_asset: [u8; 20],
    taker_asset: [u8; 20],
    making_amount: [u8; 32],
    taking_amount: [u8; 32],
    maker_traits: [u8; 32],
    signature: Vec<u8>,
    kyc_proof: Vec<[u8; 32]>,
}

#[derive(Clone, Serialize, Deserialize)]
struct BatchInput {
    chain_id: u64,
    verifying_contract: [u8; 20],
    tfund: [u8; 20],
    usdc: [u8; 20],
    kyc_root: [u8; 32],
    current_timestamp: u64,
    orders: Vec<Order>,
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
    encoded.extend_from_slice(&keccak256(
        b"EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)",
    ));
    encoded.extend_from_slice(&keccak256(b"1inch Limit Order Protocol"));
    encoded.extend_from_slice(&keccak256(b"4"));
    encoded.extend_from_slice(&uint64_word(input.chain_id));
    encoded.extend_from_slice(&address_word(&input.verifying_contract));
    keccak256(&encoded)
}

fn hash_order(order: &Order, domain_separator: &[u8; 32]) -> [u8; 32] {
    let mut encoded = Vec::with_capacity(288);
    encoded.extend_from_slice(&keccak256(b"Order(uint256 salt,address maker,address receiver,address makerAsset,address takerAsset,uint256 makingAmount,uint256 takingAmount,uint256 makerTraits)"));
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

fn amount(value: u128) -> [u8; 32] {
    let mut output = [0u8; 32];
    output[16..].copy_from_slice(&value.to_be_bytes());
    output
}

fn address_from_key(key: &SigningKey) -> [u8; 20] {
    let encoded = key.verifying_key().to_encoded_point(false);
    let digest = keccak256(&encoded.as_bytes()[1..]);
    digest[12..].try_into().unwrap()
}

fn sign_order(order: &Order, key: &SigningKey, domain_separator: &[u8; 32]) -> Vec<u8> {
    let order_hash = hash_order(order, domain_separator);
    let (signature, recovery_id) = key.sign_prehash_recoverable(&order_hash).unwrap();
    let mut output = vec![0u8; 65];
    output[..64].copy_from_slice(signature.to_bytes().as_slice());
    output[64] = recovery_id.to_byte() + 27;
    output
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

fn sample_input() -> BatchInput {
    let seller_key = SigningKey::from_bytes((&[1u8; 32]).into()).unwrap();
    let buyer_key = SigningKey::from_bytes((&[2u8; 32]).into()).unwrap();
    let seller = address_from_key(&seller_key);
    let buyer = address_from_key(&buyer_key);
    let seller_leaf = keccak256(&seller);
    let buyer_leaf = keccak256(&buyer);
    let kyc_root = sorted_pair_hash(seller_leaf, buyer_leaf);
    let domain_input = BatchInput {
        chain_id: CHAIN_ID,
        verifying_contract: EXTENSION,
        tfund: TFUND,
        usdc: USDC,
        kyc_root,
        current_timestamp: 0,
        orders: Vec::new(),
    };
    let domain_separator = hash_domain(&domain_input);
    let mut sell = Order {
        salt: amount(1),
        maker: seller,
        receiver: seller,
        maker_asset: TFUND,
        taker_asset: USDC,
        making_amount: amount(1_000_000),
        taking_amount: amount(1_000_000),
        maker_traits: [0u8; 32],
        signature: Vec::new(),
        kyc_proof: vec![buyer_leaf],
    };
    sell.signature = sign_order(&sell, &seller_key, &domain_separator);
    let mut buy = Order {
        salt: amount(2),
        maker: buyer,
        receiver: buyer,
        maker_asset: USDC,
        taker_asset: TFUND,
        making_amount: amount(1_000_000),
        taking_amount: amount(1_000_000),
        maker_traits: [0u8; 32],
        signature: Vec::new(),
        kyc_proof: vec![seller_leaf],
    };
    buy.signature = sign_order(&buy, &buyer_key, &domain_separator);
    BatchInput { orders: vec![sell, buy], ..domain_input }
}

fn load_input() -> BatchInput {
    match env::var("BATCH_INPUT_PATH") {
        Ok(path) => serde_json::from_str(
            &fs::read_to_string(path).expect("failed to read BATCH_INPUT_PATH"),
        )
        .expect("invalid batch JSON"),
        Err(_) => sample_input(),
    }
}

fn padded_length(length: usize) -> usize {
    (length + 31) / 32 * 32
}

fn push_u256_word(output: &mut Vec<u8>, value: usize) {
    output.extend_from_slice(&uint64_word(value as u64));
}

fn function_selector(signature: &str) -> [u8; 4] {
    keccak256(signature.as_bytes())[..4].try_into().unwrap()
}

fn verifier_calldata(program_vkey: [u8; 32], public_values: &[u8], proof: &[u8]) -> Vec<u8> {
    let mut output = Vec::new();
    output.extend_from_slice(&function_selector("verifyProof(bytes32,bytes,bytes)"));
    output.extend_from_slice(&program_vkey);
    push_u256_word(&mut output, 96);
    push_u256_word(&mut output, 96 + 32 + padded_length(public_values.len()));
    push_u256_word(&mut output, public_values.len());
    output.extend_from_slice(public_values);
    output.resize(output.len() + padded_length(public_values.len()) - public_values.len(), 0);
    push_u256_word(&mut output, proof.len());
    output.extend_from_slice(proof);
    output.resize(output.len() + padded_length(proof.len()) - proof.len(), 0);
    output
}

fn adapter_calldata(proof: &[u8], public_values: &[u8]) -> Vec<u8> {
    let mut output = Vec::new();
    output.extend_from_slice(&function_selector("verifyBatch(bytes,bytes)"));
    push_u256_word(&mut output, 64);
    push_u256_word(&mut output, 64 + 32 + padded_length(proof.len()));
    push_u256_word(&mut output, proof.len());
    output.extend_from_slice(proof);
    output.resize(output.len() + padded_length(proof.len()) - proof.len(), 0);
    push_u256_word(&mut output, public_values.len());
    output.extend_from_slice(public_values);
    output.resize(output.len() + padded_length(public_values.len()) - public_values.len(), 0);
    output
}

fn proof_mode() -> String {
    env::var("SP1_PROOF_MODE").unwrap_or_else(|_| "plonk".to_owned()).to_lowercase()
}

#[tokio::main]
async fn main() {
    sp1_sdk::utils::setup_logger();
    let input = load_input();
    let mut stdin = SP1Stdin::new();
    stdin.write(&input);

    let client = ProverClient::from_env().await;
    let setup_start = Instant::now();
    let proving_key: ProvingKey = client.setup(ELF).await.expect("SP1 setup failed");
    let setup_ms = setup_start.elapsed().as_millis();

    let (_, execution_report) =
        client.execute(ELF, stdin.clone()).await.expect("SP1 execution failed");
    let prove_start = Instant::now();
    let proof = match proof_mode().as_str() {
        "groth16" => {
            client.prove(&proving_key, stdin).groth16().await.expect("Groth16 proving failed")
        }
        "plonk" => client.prove(&proving_key, stdin).plonk().await.expect("Plonk proving failed"),
        mode => panic!("unsupported SP1_PROOF_MODE={mode}; use plonk or groth16"),
    };
    let prove_ms = prove_start.elapsed().as_millis();
    client
        .verify(&proof, proving_key.verifying_key(), None)
        .expect("local proof verification failed");

    let proof_bytes = proof.bytes();
    let public_values = proof.public_values.as_slice();
    let vkey = proving_key.verifying_key().bytes32_raw();
    let output_dir = PathBuf::from(
        env::var("SP1_OUTPUT_DIR").unwrap_or_else(|_| "proofs/rwa-dex-batch".to_owned()),
    );
    fs::create_dir_all(&output_dir).expect("failed to create output directory");
    fs::write(output_dir.join("proof.bin"), &proof_bytes).expect("failed to write proof");
    fs::write(output_dir.join("public-values.bin"), public_values)
        .expect("failed to write public values");
    fs::write(
        output_dir.join("verifier-calldata.bin"),
        verifier_calldata(vkey, public_values, &proof_bytes),
    )
    .expect("failed to write verifier calldata");
    fs::write(
        output_dir.join("adapter-calldata.bin"),
        adapter_calldata(&proof_bytes, public_values),
    )
    .expect("failed to write adapter calldata");

    let metrics = format!(
        "{{\n  \"proof_mode\": \"{}\",\n  \"setup_ms\": {},\n  \"proving_ms\": {},\n  \"cycles\": {},\n  \"proof_bytes\": {},\n  \"public_values_bytes\": {},\n  \"verifier_calldata_bytes\": {},\n  \"adapter_calldata_bytes\": {}\n}}\n",
        proof_mode(),
        setup_ms,
        prove_ms,
        execution_report.total_instruction_count() + execution_report.total_syscall_count(),
        proof_bytes.len(),
        public_values.len(),
        verifier_calldata(vkey, public_values, &proof_bytes).len(),
        adapter_calldata(&proof_bytes, public_values).len(),
    );
    fs::write(output_dir.join("metrics.json"), metrics).expect("failed to write metrics");

    println!("program vkey: 0x{}", hex::encode(vkey));
    println!("proof mode: {}", proof_mode());
    println!(
        "cycles: {}",
        execution_report.total_instruction_count() + execution_report.total_syscall_count()
    );
    println!("setup ms: {}, proving ms: {}", setup_ms, prove_ms);
    println!("proof bytes: {}, public values bytes: {}", proof_bytes.len(), public_values.len());
    println!(
        "verifier calldata: 0x{}",
        hex::encode(verifier_calldata(vkey, public_values, &proof_bytes))
    );
    println!("adapter calldata: 0x{}", hex::encode(adapter_calldata(&proof_bytes, public_values)));
    println!("artifacts: {}", output_dir.display());
}
