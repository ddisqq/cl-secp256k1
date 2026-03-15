;;;; Copyright (c) 2024-2026 Parkian Company LLC. All rights reserved.
;;;; SPDX-License-Identifier: Apache-2.0
;;;; This file is part of cl-secp256k1.

;;;; RFC 6979: Deterministic Usage of DSA and ECDSA
;;;; https://www.rfc-editor.org/rfc/rfc6979

(in-package #:cl-secp256k1)

;;; ============================================================================
;;; RFC 6979 Deterministic Nonce Generation
;;; ============================================================================
;;;
;;; SECURITY CRITICAL: This replaces random k-value generation with
;;; deterministic nonce generation per RFC 6979 Section 3.2.
;;;
;;; Random k-values are DANGEROUS because:
;;; - Nonce reuse leads to private key recovery (Sony PS3 exploit)
;;; - Bias in k allows lattice attacks
;;; - Poor RNG can leak key bits
;;;
;;; RFC 6979 uses HMAC-DRBG to derive k deterministically from:
;;; - Private key (x)
;;; - Message hash (h1)
;;;
;;; This ensures:
;;; - Same (message, key) always produces same signature
;;; - No dependence on RNG quality
;;; - No nonce reuse possible
;;; ============================================================================

(defun rfc6979-generate-k (private-key-bytes message-hash)
  "Generate deterministic ECDSA nonce per RFC 6979 Section 3.2.

   ALGORITHM (HMAC-DRBG with SHA-256):
   1. V = 0x01 repeated 32 times
   2. K = 0x00 repeated 32 times
   3. K = HMAC_K(V || 0x00 || private_key || message_hash)
   4. V = HMAC_K(V)
   5. K = HMAC_K(V || 0x01 || private_key || message_hash)
   6. V = HMAC_K(V)
   7. Loop until valid k found:
      - V = HMAC_K(V)
      - k = bits2int(V)
      - If 0 < k < n, return k

   PARAMETERS:
   - PRIVATE-KEY-BYTES: 32-byte private key as byte vector
   - MESSAGE-HASH: 32-byte message hash (SHA256 of message)

   RETURNS:
   Integer k suitable for ECDSA signing (0 < k < n)

   SECURITY:
   - Deterministic: Same inputs always produce same k
   - No RNG dependency: Works even with broken RNG
   - Prevents nonce reuse attacks"
  (declare (type (simple-array (unsigned-byte 8) (*)) private-key-bytes message-hash)
           (optimize (speed 3) (safety 1)))
  (let* ((n +secp256k1-n+)
         ;; Ensure inputs are proper byte vectors (32 bytes each)
         (x-bytes (if (= (length private-key-bytes) 32)
                      private-key-bytes
                      (integer-to-bytes (bytes-to-integer private-key-bytes) 32)))
         (h1-bytes (if (= (length message-hash) 32)
                       message-hash
                       (integer-to-bytes (bytes-to-integer message-hash) 32)))
         ;; Step 1: V = 0x01 repeated 32 times
         (v (make-array 32 :element-type '(unsigned-byte 8) :initial-element #x01))
         ;; Step 2: K = 0x00 repeated 32 times
         (k (make-array 32 :element-type '(unsigned-byte 8) :initial-element #x00)))

    ;; Step 3: K = HMAC_K(V || 0x00 || x || h1)
    (setf k (hmac-sha256 k (concatenate-bytes v
                                               (make-array 1 :element-type '(unsigned-byte 8)
                                                           :initial-element #x00)
                                               x-bytes
                                               h1-bytes)))
    ;; Step 4: V = HMAC_K(V)
    (setf v (hmac-sha256 k v))

    ;; Step 5: K = HMAC_K(V || 0x01 || x || h1)
    (setf k (hmac-sha256 k (concatenate-bytes v
                                               (make-array 1 :element-type '(unsigned-byte 8)
                                                           :initial-element #x01)
                                               x-bytes
                                               h1-bytes)))
    ;; Step 6: V = HMAC_K(V)
    (setf v (hmac-sha256 k v))

    ;; Step 7: Loop until valid k found
    (loop
      ;; V = HMAC_K(V)
      (setf v (hmac-sha256 k v))
      ;; k_candidate = bits2int(V)
      (let ((k-candidate (bytes-to-integer v)))
        ;; Check 0 < k < n
        (when (and (> k-candidate 0) (< k-candidate n))
          (return k-candidate)))
      ;; If invalid, update K and V and try again
      (setf k (hmac-sha256 k (concatenate-bytes v
                                                 (make-array 1 :element-type '(unsigned-byte 8)
                                                             :initial-element #x00))))
      (setf v (hmac-sha256 k v)))))
