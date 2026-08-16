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

    event BatchProofVerified(bytes32 indexed batchDigest, address indexed settlement, bytes32 programVKey);

    address public constant ERC3643_LIMIT_ORDER_EXTENSION = 0xed281B3a066A5818FE119E33fb1e1719185a8a25;
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
}
