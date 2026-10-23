# ecvrf-py

Verifiable Random Functions (VRFs) over ed25519 in pure Python — zero dependencies.

Implements the `ECVRF-EDWARDS25519-SHA512-TAI` ciphersuite from [RFC 9381](https://www.rfc-editor.org/rfc/rfc9381.html):

- **keygen / prove / verify / proof_to_hash** (RFC 9381 §4)
- **try-and-increment encode-to-curve** (§5.4.1.1), with cofactor clearing
- **deterministic nonce generation** from `(SK, h_string)` (§4.4.1)
- **challenge generation** over the five proof points (§5.5.1.1)
- self-contained **ed25519 group arithmetic** in extended coordinates

## What is a VRF?

A VRF lets a secret-key holder compute a pseudorandom output for an input
`together with a proof` that anyone can verify with the public key —
without learning the secret. Chainlink VRF, Algorand sortition and
Ethereum RANDAO-style beacons all rely on this primitive.

## Quick start

```python
from ecvrf import keygen, prove, verify, proof_to_hash

SK, PK = keygen()          # 32-byte secret and public keys
alpha = b"block:12345"

pi = prove(SK, alpha)      # 96-byte proof (Gamma || c || s)
assert verify(PK, pi, alpha)

beta = proof_to_hash(pi)   # 32-byte pseudorandom VRF output
```

The output is deterministic: the same `(SK, alpha)` always yields the same
proof and beta, while a tampered proof, a different input or a different
public key all fail verification.

## Run it

```bash
python3 ecvrf.py --demo   # walkthrough with a fresh random key
python3 ecvrf.py --test   # 15 doctests covering protocol properties
```

The doctests assert the protocol's security properties (prove/verify
round-trips, output determinism and uniqueness, rejection of tampered
proofs, wrong inputs and wrong keys) rather than RFC appendix vectors.

## Notes

- Pure Python, no dependencies — arithmetic is textbook extended-coordinate
  Edwards math, kept readable rather than constant-time; do not use for
  production key management.
- Suite ID `0x03`; proofs are 96 bytes, VRF outputs 32 bytes.
