#!/usr/bin/env python3
"""ECVRF verifiable random functions (RFC 9381) over ed25519, pure Python.

Implements the ``ECVRF-EDWARDS25519-SHA512-TAI`` ciphersuite:

* keygen / prove / verify / proof_to_hash following RFC 9381 section 4,
* try-and-increment encode-to-curve (section 5.4.1.1),
* deterministic nonce generation from (SK, h_string) (section 4.4.1),
* challenge generation over the five proof points (section 5.5.1.1),
* self-contained ed25519 group arithmetic (extended coordinates).

No third-party dependencies.

Doctests assert the protocol's security properties (correctness of
prove/verify round-trips, determinism of the VRF output, rejection of
tampered proofs, wrong inputs and wrong keys) rather than RFC appendix
vectors.

>>> SK = bytes.fromhex("0123456789abcdef" * 4)
>>> pk = public_key(SK)
>>> alpha = b"block:12345"
>>> pi = prove(SK, alpha)
>>> len(pi)
96
>>> verify(pk, pi, alpha)
True
>>> len(proof_to_hash(pi))  # 32-byte VRF output
32
>>> vrf_output(SK, alpha) == vrf_output(SK, alpha)  # deterministic
True
>>> vrf_output(SK, b"block:12346") != vrf_output(SK, alpha)  # distinct inputs
True

A tampered proof, a different input or a different public key all fail:

>>> bad = bytearray(pi); bad[50] ^= 0x01
>>> verify(pk, bytes(bad), alpha)
False
>>> verify(pk, pi, b"block:12346")
False
>>> verify(encode(scalar_mult(12345, G)), pi, alpha)
False

Ed25519 plumbing sanity: encode/decode round-trip and the group order:

>>> encode(decode(pk)) == pk
True
>>> scalar_mult(q, G) == IDENTITY
True
"""

import argparse
import doctest
import hashlib
import secrets

# ---------------------------------------------------------------------------
# ed25519 group arithmetic (extended coordinates)
# ---------------------------------------------------------------------------

p = 2**255 - 19
d = (-121665 * pow(121666, p - 2, p)) % p
q = 2**252 + 27742317777372353535851937790883648493  # ed25519 group order

Gx = 0x216936D3CD6E53FEC0A4E231FDD6DC5C692CC7609525A7B2C9562D608F25D51A
Gy = 0x6666666666666666666666666666666666666666666666666666666666666658

IDENTITY = (0, 1, 1, 0)
G = (Gx, Gy, 1, (Gx * Gy) % p)


def modinv(a):
    return pow(a, p - 2, p)


def point_add(P, Q):
    """Extended-coordinate Edwards addition (Hisil et al. formulas)."""
    X1, Y1, Z1, T1 = P
    X2, Y2, Z2, T2 = Q
    A = ((Y1 - X1) * (Y2 - X2)) % p
    B = ((Y1 + X1) * (Y2 + X2)) % p
    C = (T1 * (2 * d % p) * T2) % p
    D = (Z1 * 2 * Z2) % p
    E = (B - A) % p
    F = (D - C) % p
    GG = (D + C) % p
    H = (B + A) % p
    return ((E * F) % p, (GG * H) % p, (F * GG) % p, (E * H) % p)


def scalar_mult(s, P):
    """Double-and-add scalar multiplication; s reduced mod q."""
    s = s % q
    R = IDENTITY
    while s:
        if s & 1:
            R = point_add(R, P)
        P = point_add(P, P)
        s >>= 1
    return R


def encode(P):
    """Compressed 32-byte little-endian encoding (top bit = x odd)."""
    X, Y, Z, T = P
    zinv = modinv(Z)
    x = (X * zinv) % p
    y = (Y * zinv) % p
    b = bytearray(y.to_bytes(32, "little"))
    b[31] |= (x & 1) << 7
    return bytes(b)


def _sqrt_mod_p(v):
    """Square root mod p (p = 5 mod 8); raises ValueError if none exists."""
    x = pow(v, (p + 5) // 8, p)
    if (x * x) % p != v % p:
        x = (x * pow(2, (p - 1) // 4, p)) % p
    if (x * x) % p != v % p:
        raise ValueError("no square root")
    return x


def decode(s):
    """Decode a compressed point; raises ValueError on invalid input."""
    if len(s) != 32:
        raise ValueError("compressed point must be 32 bytes")
    b = bytearray(s)
    x_bit = b[31] >> 7
    b[31] &= 0x7F
    y = int.from_bytes(b, "little")
    if y >= p:
        raise ValueError("y out of range")
    x = _sqrt_mod_p(((y * y - 1) * modinv((d * y * y + 1) % p)) % p)
    if (x & 1) != x_bit:
        x = p - x
    if ((y * y - x * x - 1 - d * x * x % p * y * y) % p) != 0:  # -x^2 + y^2 = 1 + d x^2 y^2
        raise ValueError("point not on curve")
    return (x, y, 1, (x * y) % p)


# ---------------------------------------------------------------------------
# ECVRF-EDWARDS25519-SHA512-TAI (RFC 9381)
# ---------------------------------------------------------------------------

SUITE_STRING = b"\x03"  # suite ID 0x03


def _secret_scalar(SK):
    if len(SK) != 32:
        raise ValueError("secret key must be 32 bytes")
    x = int.from_bytes(SK, "little") % q
    if x == 0:
        raise ValueError("degenerate secret key")
    return x


def _encode_to_curve(data):
    """Try-and-increment encode-to-curve (RFC 9381, 5.4.1.1) + cofactor clear."""
    for ctr in range(256):
        attempt = SUITE_STRING + b"\x01" + data + bytes((ctr, 0x00))
        candidate = bytearray(hashlib.sha512(attempt).digest()[:32])
        candidate[31] &= 0x7F
        x = int.from_bytes(candidate, "little")
        try:
            y = _sqrt_mod_p(((x * x - 1) * modinv((d * x * x + 1) % p)) % p)
        except ValueError:
            continue
        if y & 1:
            y = p - y
        P = (x, y, 1, (x * y) % p)
        return scalar_mult(8, P)  # clear the cofactor
    raise RuntimeError("encode-to-curve failed (practically impossible)")


def _challenge(Y, H, Gamma, U, V):
    """Challenge generation over the five proof points (RFC 9381, 5.5.1.1)."""
    data = SUITE_STRING + b"\x02" + b"".join(encode(P) for P in (Y, H, Gamma, U, V))
    return int.from_bytes(hashlib.sha512(data).digest(), "big") % q


def _nonce(SK, h_string):
    """Deterministic nonce from (SK, h_string) (RFC 9381, 4.4.1)."""
    k = int.from_bytes(hashlib.sha512(SK + h_string).digest(), "big") % q
    if k == 0:
        raise RuntimeError("degenerate nonce (practically impossible)")
    return k


def keygen():
    """Generate a fresh (SK, PK) pair; PK is the compressed 32-byte encoding."""
    SK = secrets.token_bytes(32)
    return SK, public_key(SK)


def public_key(SK):
    """Derive the compressed public key from a secret key."""
    return encode(scalar_mult(_secret_scalar(SK), G))


def prove(SK, alpha):
    """Create a 96-byte VRF proof for input alpha (bytes)."""
    if not isinstance(alpha, (bytes, bytearray)):
        raise TypeError("alpha must be bytes")
    x = _secret_scalar(SK)
    Y = scalar_mult(x, G)
    H = _encode_to_curve(encode(Y) + bytes(alpha))
    Gamma = scalar_mult(x, H)
    k = _nonce(SK, encode(H))
    U = scalar_mult(k, G)
    V = scalar_mult(k, H)
    c = _challenge(Y, H, Gamma, U, V)
    s = (k - c * x) % q
    return encode(Gamma) + c.to_bytes(32, "big") + s.to_bytes(32, "big")


def _decode_proof(pi):
    if len(pi) != 96:
        raise ValueError("proof must be 96 bytes")
    Gamma = decode(bytes(pi[:32]))
    c = int.from_bytes(pi[32:64], "big")
    s = int.from_bytes(pi[64:96], "big")
    if not (0 <= c < q and 0 <= s < q):
        raise ValueError("challenge/response out of range")
    return Gamma, c, s


def verify(PK, pi, alpha):
    """Verify a VRF proof. Returns True/False, never raises."""
    try:
        Y = decode(bytes(PK))
        Gamma, c, s = _decode_proof(pi)
    except ValueError:
        return False
    H = _encode_to_curve(encode(Y) + bytes(alpha))
    U = point_add(scalar_mult(s, G), scalar_mult(c, Y))
    V = point_add(scalar_mult(s, H), scalar_mult(c, Gamma))
    return _challenge(Y, H, Gamma, U, V) == c


def proof_to_hash(pi):
    """Map a proof to the 32-byte VRF output (beta)."""
    Gamma, _c, _s = _decode_proof(pi)
    return encode(_encode_to_curve(encode(Gamma)))


def vrf_output(SK, alpha):
    """Convenience: prove and hash in one call."""
    return proof_to_hash(prove(SK, alpha))


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------


def demo():
    SK, PK = keygen()
    alpha = b"block:12345"
    pi = prove(SK, alpha)
    print("ECVRF-EDWARDS25519-SHA512-TAI demo")
    print(f"  secret key (kept private): {SK.hex()}")
    print(f"  public key               : {PK.hex()}")
    print(f"  input alpha              : {alpha!r}")
    print(f"  proof                    : {pi.hex()[:32]}... ({len(pi)} bytes)")
    print(f"  VRF output (beta)        : {proof_to_hash(pi).hex()}")
    print(f"  verify                   : {verify(PK, pi, alpha)}")
    print(f"  verify wrong input       : {verify(PK, pi, b'block:12346')}")


def main():
    ap = argparse.ArgumentParser(description="ECVRF (RFC 9381) over ed25519 demo")
    ap.add_argument("--demo", action="store_true", help="run the walkthrough demo")
    ap.add_argument("--test", action="store_true", help="run the doctests")
    args = ap.parse_args()
    if args.test:
        failed, attempted = doctest.testmod(verbose=False)
        print(f"doctests: {attempted - failed}/{attempted} passed")
        raise SystemExit(1 if failed else 0)
    demo()


if __name__ == "__main__":
    main()
