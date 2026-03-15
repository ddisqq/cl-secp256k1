;;;; Copyright (c) 2024-2026 Parkian Company LLC. All rights reserved.
;;;; SPDX-License-Identifier: Apache-2.0
;;;; This file is part of cl-secp256k1.

(defpackage #:cl-secp256k1
  (:use #:cl)
  (:documentation "Pure Common Lisp secp256k1 ECDSA implementation.

This package provides complete ECDSA signing and verification on the secp256k1
elliptic curve used by Bitcoin. All operations are implemented in pure Common
Lisp with zero external dependencies.

Key Features:
- RFC 6979 deterministic nonce generation (prevents nonce reuse attacks)
- BIP-62 low-S signature normalization (malleability fix)
- SEC1 public key serialization (compressed and uncompressed)
- DER signature encoding/decoding
- Pure field arithmetic and point operations

Security Note:
This implementation is suitable for signing and verification but is NOT
constant-time. For production use with secret keys in adversarial environments,
consider using hardware security modules or constant-time implementations.")

  ;; Curve parameters
  (:export #:+secp256k1-p+
           #:+secp256k1-n+
           #:+secp256k1-gx+
           #:+secp256k1-gy+)

  ;; Field arithmetic
  (:export #:mod-add
           #:mod-sub
           #:mod-mul
           #:mod-inverse
           #:mod-expt
           #:mod-sqrt)

  ;; Point operations
  (:export #:point-at-infinity-p
           #:point-add
           #:point-double
           #:point-multiply
           #:point-negate
           #:generator-point
           #:valid-point-p)

  ;; Key operations
  (:export #:generate-private-key
           #:private-key-to-public
           #:valid-private-key-p
           #:valid-public-key-p
           #:serialize-public-key
           #:parse-public-key)

  ;; ECDSA operations
  (:export #:ecdsa-sign
           #:ecdsa-verify
           #:ecdsa-sign-hash
           #:ecdsa-verify-hash)

  ;; Signature encoding
  (:export #:der-encode-signature
           #:der-decode-signature
           #:compact-encode-signature
           #:compact-decode-signature)

  ;; Utilities
  (:export #:bytes-to-integer
           #:integer-to-bytes
           #:sha256
           #:sha256d
           #:random-bytes))

(defpackage #:cl-secp256k1.test
  (:use #:cl #:cl-secp256k1)
  (:export #:run-tests))
