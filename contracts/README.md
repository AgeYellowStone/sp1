# SP1 Batch Verifier

`SP1BatchVerifier.sol` is an adapter for the Stage 1 settlement deployment:

`0xed281B3a066A5818FE119E33fb1e1719185a8a25`

The constructor takes the official Succinct SP1 verifier address and the generated
program verification-key hash. It calls the exact SP1 ABI:

```solidity
verifyProof(bytes32 programVKey, bytes publicValues, bytes proofBytes)
```

The adapter records `keccak256(publicValues)` after successful verification. The
Stage 1 settlement contract predates batch settlement and has no
`settleVerifiedBatch` entrypoint, so state-changing batch settlement is intentionally
not faked here. A future settlement upgrade can consume `verifiedBatches` and bind
its order matrix to the recorded digest.

## Public Values

The guest commits the following fixed-width byte stream:

| Offset | Size | Field |
| ---: | ---: | --- |
| 0 | 4 | ASCII `RWA1` |
| 4 | 8 | Chain ID, big-endian |
| 12 | 8 | Batch timestamp, big-endian |
| 20 | 20 | EIP-712 verifying contract |
| 40 | 20 | TFUND address |
| 60 | 20 | USDC address |
| 80 | 20 | IdentityRegistry address |
| 100 | 32 | EIP-712 domain separator |
| 132 | 32 | Merkle KYC root |
| 164 | 32 | Orderbook Merkle root |
| 196 | 4 | Order count, big-endian |
| 200 | 4 | Trade count, big-endian |
| 204 | `72 * count` | Trade matrix entries |

Each trade entry is `sellerIndex[4] || buyerIndex[4] || tfundAmount[32] || usdcAmount[32]`.

The guest verifies the 1inch EIP-712 order hash, recoverable secp256k1 signature,
sorted-pair Keccak Merkle proofs, TFUND/USDC asset direction, expiry, and crossing
prices before committing this output. The verifier adapter additionally binds the
public values to the configured Stage 1 settlement, TFUND, IdentityRegistry, and
USDC, Arbitrum Sepolia chain ID, and rejects snapshots older than the current block.
The Stage 1 extension predates batch settlement; its
upgrade must call `consumeVerifiedBatch` after applying the committed matrix.
