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
/// @notice Validates the canonical single-order public values used by the RWA settlement.
/// @dev The settlement address and order assets are deployment parameters. No live
///      address is embedded in the verifier bytecode.
contract SP1BatchVerifier {
    error ZeroAddress();
    error ZeroProgramVKey();
    error MalformedPublicValues();
    error WrongChainId();
    error WrongSettlement();
    error WrongRouter();
    error WrongTfund();
    error WrongSettlementToken();
    error WrongProgramVKey();
    error BatchNotVerified();

    event BatchProofVerified(bytes32 indexed batchDigest, address indexed settlement, bytes32 programVKey);
    event BatchConsumed(bytes32 indexed batchDigest, address indexed settlement);

    uint256 public constant CHAIN_ID = 421614;
    address public immutable settlement;
    address public immutable router;
    address public immutable tfund;
    address public immutable settlementToken;
    ISP1Verifier public immutable sp1Verifier;
    bytes32 public immutable programVKey;
    mapping(bytes32 batchDigest => bool verified) public verifiedBatches;

    constructor(
        address _settlement,
        address _router,
        address _tfund,
        address _settlementToken,
        address _sp1Verifier,
        bytes32 _programVKey
    ) {
        if (
            _settlement == address(0)
                || _router == address(0)
                || _tfund == address(0)
                || _settlementToken == address(0)
                || _sp1Verifier == address(0)
        ) revert ZeroAddress();
        if (
            _settlement.code.length == 0
                || _router.code.length == 0
                || _tfund.code.length == 0
                || _settlementToken.code.length == 0
                || _sp1Verifier.code.length == 0
        ) revert ZeroAddress();
        if (_programVKey == bytes32(0)) revert ZeroProgramVKey();

        settlement = _settlement;
        router = _router;
        tfund = _tfund;
        settlementToken = _settlementToken;
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
        // abi.encode(chainId, router, orderHash, maker, logicalTaker,
        //            makerAsset, takerAsset, makingAmount, takingAmount,
        //            fillMakingAmount, fillTakingAmount, settlementNonce,
        //            matchingCommitment)
        if (publicValues.length != 13 * 32) revert MalformedPublicValues();

        (
            uint256 chainId,
            address provenRouter,
            bytes32 orderHash,
            address maker,
            address logicalTaker,
            address makerAsset,
            address takerAsset,
            uint256 makingAmount,
            uint256 takingAmount,
            uint256 fillMakingAmount,
            uint256 fillTakingAmount,
            uint256 settlementNonce,
            bytes32 matchingCommitment
        ) = abi.decode(
            publicValues,
            (
                uint256,
                address,
                bytes32,
                address,
                address,
                address,
                address,
                uint256,
                uint256,
                uint256,
                uint256,
                uint256,
                bytes32
            )
        );

        if (chainId != CHAIN_ID) revert WrongChainId();
        if (provenRouter != router) revert WrongRouter();
        if (orderHash == bytes32(0) || maker == address(0) || logicalTaker == address(0)) {
            revert MalformedPublicValues();
        }
        if (makerAsset != tfund) revert WrongTfund();
        if (takerAsset != settlementToken) revert WrongSettlementToken();
        if (
            makingAmount == 0
                || takingAmount == 0
                || fillMakingAmount == 0
                || fillTakingAmount == 0
                || matchingCommitment == bytes32(0)
        ) revert MalformedPublicValues();

        bytes32 expectedCommitment = keccak256(
            abi.encodePacked(orderHash, logicalTaker, fillMakingAmount, settlementNonce)
        );
        if (matchingCommitment != expectedCommitment) revert MalformedPublicValues();
    }
}
