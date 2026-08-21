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
/// @notice Validates the canonical packed public values used by batch settlement.
/// @dev The settlement address and order assets are deployment parameters. No live
///      address is embedded in the verifier bytecode.
contract SP1BatchVerifier {
    error ZeroAddress();
    error ZeroProgramVKey();
    error MalformedPublicValues();
    error WrongChainId();
    error WrongSettlement();
    error WrongRouter();
    error WrongProgramVKey();
    error BatchNotVerified();

    event BatchProofVerified(bytes32 indexed batchDigest, address indexed settlement, bytes32 programVKey);
    event BatchConsumed(bytes32 indexed batchDigest, address indexed settlement);

    uint256 public constant CHAIN_ID = 421614;
    uint256 public constant MAX_ORDERS = 128;
    uint256 public constant MAX_TRADES = 256;
    address public immutable settlement;
    address public immutable router;
    address public immutable identityRegistry;
    ISP1Verifier public immutable sp1Verifier;
    bytes32 public immutable programVKey;
    mapping(bytes32 batchDigest => bool verified) public verifiedBatches;

    constructor(
        address _settlement,
        address _router,
        address _identityRegistry,
        address _sp1Verifier,
        bytes32 _programVKey
    ) {
        if (
            _settlement == address(0)
                || _router == address(0)
                || _identityRegistry == address(0)
                || _sp1Verifier == address(0)
        ) revert ZeroAddress();
        if (
            _settlement.code.length == 0
                || _router.code.length == 0
                || _identityRegistry.code.length == 0
                || _sp1Verifier.code.length == 0
        ) revert ZeroAddress();
        if (_programVKey == bytes32(0)) revert ZeroProgramVKey();

        settlement = _settlement;
        router = _router;
        identityRegistry = _identityRegistry;
        sp1Verifier = ISP1Verifier(_sp1Verifier);
        programVKey = _programVKey;
    }

    /// @notice Succinct-compatible verifier entrypoint. Success is represented by no revert.
    function verifyProof(bytes32 suppliedVKey, bytes calldata publicValues, bytes calldata proofBytes)
        external
        view
    {
        _verifyProof(suppliedVKey, publicValues, proofBytes);
    }

    /// @notice Verifies proof bytes and returns the committed public-values digest.
    function verifyBatch(bytes calldata proofBytes, bytes calldata publicValues)
        public
        view
        returns (bytes32 batchDigest)
    {
        _verifyProof(programVKey, publicValues, proofBytes);
        return keccak256(publicValues);
    }

    /// @notice Records a verified digest for an integration that consumes it atomically.
    function recordVerifiedBatch(bytes calldata proofBytes, bytes calldata publicValues)
        external
        returns (bytes32 batchDigest)
    {
        batchDigest = verifyBatch(proofBytes, publicValues);
        verifiedBatches[batchDigest] = true;
        emit BatchProofVerified(batchDigest, settlement, programVKey);
    }

    /// @notice Allows only the configured settlement contract to consume a digest once.
    function consumeVerifiedBatch(bytes32 batchDigest) external {
        if (msg.sender != settlement) revert WrongSettlement();
        if (!verifiedBatches[batchDigest]) revert BatchNotVerified();
        verifiedBatches[batchDigest] = false;
        emit BatchConsumed(batchDigest, settlement);
    }

    function _verifyProof(bytes32 suppliedVKey, bytes calldata publicValues, bytes calldata proofBytes)
        internal
        view
    {
        if (suppliedVKey != programVKey) revert WrongProgramVKey();
        _validatePublicValues(publicValues);
        sp1Verifier.verifyProof(programVKey, publicValues, proofBytes);
    }

    function _validatePublicValues(bytes calldata publicValues) internal view {
        // RWA1 | chainId(8) | timestamp(8) | settlement(20) | router(20) |
        // identityRegistry(20) | kycRoot | orderbookRoot | orderCount(4) |
        // tradeCount(4) | tradesHash.
        if (publicValues.length != 184) revert MalformedPublicValues();
        uint256 offset;
        uint256 chainId;
        uint256 batchTimestamp;
        address provenSettlement;
        address provenRouter;
        address identityRegistry;
        bytes32 kycRoot;
        bytes32 orderbookRoot;
        uint256 orderCount;
        uint256 tradeCount;
        bytes32 tradesHash;
        assembly {
            offset := publicValues.offset
            if iszero(eq(shr(224, calldataload(offset)), 0x52574131)) { revert(0, 0) }
            chainId := shr(192, calldataload(add(offset, 4)))
            batchTimestamp := shr(192, calldataload(add(offset, 12)))
            provenSettlement := shr(96, calldataload(add(offset, 20)))
            provenRouter := shr(96, calldataload(add(offset, 40)))
            identityRegistry := shr(96, calldataload(add(offset, 60)))
            kycRoot := calldataload(add(offset, 80))
            orderbookRoot := calldataload(add(offset, 112))
            orderCount := shr(224, calldataload(add(offset, 144)))
            tradeCount := shr(224, calldataload(add(offset, 148)))
            tradesHash := calldataload(add(offset, 152))
        }
        if (chainId != block.chainid || chainId != CHAIN_ID) revert WrongChainId();
        if (batchTimestamp == 0 || batchTimestamp > block.timestamp) revert MalformedPublicValues();
        if (provenSettlement != settlement) revert WrongSettlement();
        if (provenRouter != router) revert WrongRouter();
        if (
            identityRegistry != address(this.identityRegistry)
                || kycRoot == bytes32(0)
                || orderbookRoot == bytes32(0)
                || tradesHash == bytes32(0)
                || orderCount == 0
                || orderCount > MAX_ORDERS
                || tradeCount == 0
                || tradeCount > MAX_TRADES
        ) revert MalformedPublicValues();
    }
}
