# cl-secp256k1

Pure Common Lisp implementation of secp256k1 elliptic curve ECDSA with **zero external dependencies**.

## Features

- **Pure Common Lisp**: No CFFI, no OpenSSL, no external libraries
- **RFC 6979**: Deterministic nonce generation (prevents nonce reuse attacks)
- **BIP-62**: Low-S signature normalization (malleability fix)
- **SEC1**: Compressed and uncompressed public key serialization
- **DER**: Standard signature encoding/decoding
- **SHA-256**: Inlined FIPS 180-4 compliant implementation
- **HMAC-SHA256**: For RFC 6979 HMAC-DRBG

## Installation

Clone the repository and load with ASDF:

```lisp
(asdf:load-system :cl-secp256k1)
```

## Quick Start

```lisp
(use-package :cl-secp256k1)

;; Generate a keypair
(let* ((private-key (generate-private-key))
       (public-key (private-key-to-public private-key)))

  ;; Sign a message
  (let* ((message "Hello, Bitcoin!")
         (hash (sha256 (map '(vector (unsigned-byte 8)) #'char-code message)))
         (signature (ecdsa-sign hash private-key)))

    ;; Verify the signature
    (ecdsa-verify hash signature public-key)))  ; => T
```

## API Reference

### Curve Parameters

- `+secp256k1-p+` - Field prime (2^256 - 2^32 - 977)
- `+secp256k1-n+` - Order of generator point
- `+secp256k1-gx+` - Generator point X coordinate
- `+secp256k1-gy+` - Generator point Y coordinate

### Field Arithmetic

- `(mod-add a b &optional p)` - Modular addition
- `(mod-sub a b &optional p)` - Modular subtraction
- `(mod-mul a b &optional p)` - Modular multiplication
- `(mod-inverse a &optional n)` - Modular multiplicative inverse
- `(mod-expt base exp &optional mod)` - Modular exponentiation
- `(mod-sqrt n &optional p)` - Modular square root

### Point Operations

- `(generator-point)` - Returns the generator point G
- `(point-at-infinity-p point)` - Check if point is identity
- `(point-add p1 p2)` - Add two points
- `(point-double point)` - Double a point
- `(point-multiply k point)` - Scalar multiplication
- `(point-negate point)` - Negate a point
- `(valid-point-p point)` - Check if point is on curve

### Key Operations

- `(generate-private-key)` - Generate random private key
- `(private-key-to-public private-key)` - Derive public key
- `(valid-private-key-p key)` - Validate private key
- `(valid-public-key-p point)` - Validate public key
- `(serialize-public-key point &key compressed)` - Serialize to bytes
- `(parse-public-key bytes)` - Parse from bytes

### ECDSA Operations

- `(ecdsa-sign message-hash private-key)` - Sign message hash
- `(ecdsa-verify message-hash signature public-key)` - Verify signature
- `(ecdsa-sign-hash hash private-key)` - Alias for ecdsa-sign
- `(ecdsa-verify-hash hash signature public-key)` - Alias for ecdsa-verify

### Signature Encoding

- `(der-encode-signature r s)` - Encode to DER format
- `(der-decode-signature der)` - Decode from DER format
- `(compact-encode-signature r s)` - Encode to 64-byte format
- `(compact-decode-signature bytes)` - Decode from 64-byte format

### Utilities

- `(sha256 data)` - Compute SHA-256 hash
- `(sha256d data)` - Compute double SHA-256
- `(bytes-to-integer bytes &key big-endian)` - Convert bytes to integer
- `(integer-to-bytes integer n-bytes &key big-endian)` - Convert integer to bytes
- `(random-bytes n)` - Generate cryptographically secure random bytes

## Security Considerations

**WARNING**: This implementation is NOT constant-time. Execution time varies with input values, making it vulnerable to timing side-channel attacks.

**Suitable for:**
- Testing and verification
- Educational purposes
- Environments without OpenSSL
- Audit and review (fully readable code)

**Not suitable for:**
- Production signing with secret keys in adversarial environments
- High-performance applications
- Security-critical deployments with side-channel threats

For production use with secret keys in adversarial environments, consider using hardware security modules or constant-time implementations.

## Standards Compliance

- **FIPS 186-5**: Digital Signature Standard (ECDSA)
- **SEC 1 v2.0**: Elliptic Curve Cryptography (point encoding)
- **SEC 2 v2.0**: Recommended Elliptic Curve Domain Parameters (secp256k1)
- **RFC 6979**: Deterministic Usage of DSA and ECDSA
- **FIPS 180-4**: Secure Hash Standard (SHA-256)
- **RFC 2104**: HMAC
- **BIP-62**: Low-S signature normalization

## Testing

```lisp
(asdf:test-system :cl-secp256k1)
```

Or manually:

```lisp
(asdf:load-system :cl-secp256k1/test)
(cl-secp256k1.test:run-tests)
```

## License

BSD-3-Clause

Copyright (c) 2024-2026 Parkian Company LLC. All rights reserved.
