# SP1 Settlement Verifier

`SP1BatchVerifier.sol` is a deployment-parameterized adapter for the canonical
RWA order settlement. It receives the settlement, 1inch router, TFUND,
settlement-token, official Succinct verifier, and generated program vKey in its
constructor. No live settlement address is embedded in the bytecode.

It exposes the exact Succinct SP1 ABI:

```solidity
verifyProof(bytes32 programVKey, bytes publicValues, bytes proofBytes)
```

The function has no return value. A valid proof returns normally; an invalid proof
reverts. The adapter also retains the optional digest recording/consumption hook,
which is restricted to the configured settlement address.

## Public Values

The guest commits `abi.encode`-compatible static words:

| Word | Field |
| ---: | --- |
| 0 | `uint256 chainId` |
| 1 | `address router` |
| 2 | `bytes32 orderHash` |
| 3 | `address maker` |
| 4 | `address logicalTaker` |
| 5 | `address makerAsset` |
| 6 | `address takerAsset` |
| 7 | `uint256 makingAmount` |
| 8 | `uint256 takingAmount` |
| 9 | `uint256 fillMakingAmount` |
| 10 | `uint256 fillTakingAmount` |
| 11 | `uint256 settlementNonce` (`makerTraits.nonceOrEpoch()`) |
| 12 | `bytes32 matchingCommitment` |

The total public value length is exactly `13 * 32 = 416` bytes. The guest verifies
the 1inch EIP-712 order hash, recoverable secp256k1 signature, order expiry,
asset pair, private-order recipient, 512-bit checked fill ratio, and a bounded
Merkle witness before committing this output. Phase 1 accepts only EOA
secp256k1 signatures; EIP-1271 contract wallets are reserved for Phase 2. The
settlement wrapper additionally binds every word to the calldata order,
consumes the matching commitment once, and performs authoritative live
`IdentityRegistry.isVerified` checks for maker and logical taker.
