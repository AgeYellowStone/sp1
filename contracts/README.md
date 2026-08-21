# SP1 Batch Settlement Verifier

`SP1BatchVerifier.sol` is a deployment-parameterized Succinct adapter for the
batch matching-engine proof. It validates the packed public-values header and
then forwards the exact `verifyProof(bytes32,bytes,bytes)` call to the official
SP1 verifier. `verifiedBatches` records a `keccak256(publicValues)` digest for
settlement integrations that consume proof results separately.

## Public Values

The guest and Solidity batch settlement use the same 184-byte layout:

```text
RWA1(4) |
chainId(8) |
batchTimestamp(8) |
verifyingContract(20) |
limitOrderProtocol(20) |
identityRegistry(20) |
kycRoot(32) |
orderbookRoot(32) |
orderCount(4) |
tradeCount(4) |
tradesHash(32)
```

`tradesHash` is `keccak256(abi.encode(TradeSettlement[]))`. The settlement
contract compares it with its calldata array before any token transfer.
