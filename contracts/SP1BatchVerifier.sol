// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

interface ISP1Verifier {
    function verifyProof(
        bytes32 programVKey,
        bytes calldata publicValues,
        bytes calldata proofBytes
    ) external view;
}

/// @title SP1BatchVerifier
/// @notice Verifies an SP1 Plonk/Groth16 batch proof for the deployed RWA settlement.
/// @dev The settlement contract is intentionally immutable. The current Stage 1
///      deployment does not expose a batch-settlement entrypoint, so this adapter
///      records a verified public-values digest for a settlement integration to consume.
contract SP1BatchVerifier {
    error ZeroAddress();
    error ZeroProgramVKey();
    error MalformedPublicValues();
    error WrongChainId();
    error StaleBatchTimestamp();
    error WrongSettlement();
    error WrongTfund();
    error WrongUsdc();
    error WrongIdentityRegistry();
    error BatchNotVerified();

    event BatchProofVerified(bytes32 indexed batchDigest, address indexed settlement, bytes32 programVKey);
    event BatchConsumed(bytes32 indexed batchDigest, address indexed settlement);

    address public constant ERC3643_LIMIT_ORDER_EXTENSION = 0xed281B3a066A5818FE119E33fb1e1719185a8a25;
    address public constant TFUND = 0x4f955D0B96C20e88E5da6f632057e0BfA62c871e;
    address public constant USDC = 0x17B9002eaeAeD3734C357C9662DEA5DD49aAA2cE;
    address public constant IDENTITY_REGISTRY = 0xa8FAe60a6823A7e2EEe1e9dc73625537DE4E1ac6;
    uint64 public constant CHAIN_ID = 421614;
    address public immutable settlement;
    ISP1Verifier public immutable sp1Verifier;
    bytes32 public immutable programVKey;
    mapping(bytes32 batchDigest => bool verified) public verifiedBatches;

    constructor(address _sp1Verifier, bytes32 _programVKey) {
        if (_sp1Verifier == address(0)) revert ZeroAddress();
        if (_programVKey == bytes32(0)) revert ZeroProgramVKey();
        sp1Verifier = ISP1Verifier(_sp1Verifier);
        settlement = ERC3643_LIMIT_ORDER_EXTENSION;
        programVKey = _programVKey;
    }

    /// @notice Verifies proof bytes and returns the digest committed by the batch.
    function verifyBatch(bytes calldata proofBytes, bytes calldata publicValues)
        public
        view
        returns (bytes32 batchDigest)
    {
        _validatePublicValues(publicValues);
        sp1Verifier.verifyProof(programVKey, publicValues, proofBytes);
        return keccak256(publicValues);
    }

    /// @notice Verifies and records a batch digest for the settlement integration.
    function recordVerifiedBatch(bytes calldata proofBytes, bytes calldata publicValues)
        external
        returns (bytes32 batchDigest)
    {
        batchDigest = verifyBatch(proofBytes, publicValues);
        verifiedBatches[batchDigest] = true;
        emit BatchProofVerified(batchDigest, settlement, programVKey);
    }

    /// @notice Allows the configured settlement contract to consume a verified batch once.
    /// @dev The Stage 1 extension is immutable and does not currently call this hook. A settlement
    ///      upgrade can use it to make proof replay impossible after applying the matrix.
    function consumeVerifiedBatch(bytes32 batchDigest) external {
        if (msg.sender != settlement) revert WrongSettlement();
        if (!verifiedBatches[batchDigest]) revert BatchNotVerified();
        verifiedBatches[batchDigest] = false;
        emit BatchConsumed(batchDigest, settlement);
    }

    function _validatePublicValues(bytes calldata publicValues) internal view {
        // RWA1 || chainId || batchTimestamp || verifyingContract || tfund || usdc ||
        // identityRegistry || domainSeparator || kycRoot || orderbookRoot || orderCount ||
        // tradeCount.
        if (publicValues.length < 204) revert MalformedPublicValues();

        uint256 chainId;
        uint256 batchTimestamp;
        address verifyingContract;
        address tfund;
        address usdc;
        address identityRegistry;
        uint256 orderCount;
        uint256 tradeCount;
        uint256 magic;
        assembly {
            let offset := publicValues.offset
            magic := shr(224, calldataload(offset))
            chainId := shr(192, calldataload(add(offset, 4)))
            batchTimestamp := shr(192, calldataload(add(offset, 12)))
            verifyingContract := shr(96, calldataload(add(offset, 20)))
            tfund := shr(96, calldataload(add(offset, 40)))
            usdc := shr(96, calldataload(add(offset, 60)))
            identityRegistry := shr(96, calldataload(add(offset, 80)))
            orderCount := shr(224, calldataload(add(offset, 196)))
            tradeCount := shr(224, calldataload(add(offset, 200)))
        }

        if (magic != 0x52574131) revert MalformedPublicValues();
        if (chainId != CHAIN_ID) revert WrongChainId();
        if (batchTimestamp < block.timestamp) revert StaleBatchTimestamp();
        if (verifyingContract != settlement) revert WrongSettlement();
        if (tfund != TFUND) revert WrongTfund();
        if (usdc != USDC) revert WrongUsdc();
        if (identityRegistry != IDENTITY_REGISTRY) revert WrongIdentityRegistry();
        if (orderCount == 0 || orderCount > 64 || tradeCount == 0 || tradeCount > orderCount * orderCount) {
            revert MalformedPublicValues();
        }
        if (publicValues.length != 204 + tradeCount * 72) revert MalformedPublicValues();
    }
}
