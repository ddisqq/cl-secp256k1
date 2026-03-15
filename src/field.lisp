;;;; Copyright (c) 2024-2026 Parkian Company LLC. All rights reserved.
;;;; SPDX-License-Identifier: Apache-2.0
;;;; This file is part of cl-secp256k1.

;;;; Field arithmetic for secp256k1 elliptic curve operations

(in-package #:cl-secp256k1)

;;; ============================================================================
;;; secp256k1 Curve Parameters (SEC 2: Section 2.4.1)
;;; ============================================================================

(defconstant +secp256k1-p+
  #xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F
  "Field prime p = 2^256 - 2^32 - 977.
   The finite field F_p over which secp256k1 is defined.")

(defconstant +secp256k1-n+
  #xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
  "Order of the generator point G.
   All private keys must be in range [1, n-1].")

(defconstant +secp256k1-gx+
  #x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798
  "X coordinate of generator point G.")

(defconstant +secp256k1-gy+
  #x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8
  "Y coordinate of generator point G.")

;;; ============================================================================
;;; Modular Arithmetic Operations
;;; ============================================================================

(defun mod-add (a b &optional (p +secp256k1-p+))
  "Modular addition: (a + b) mod p.

   PARAMETERS:
   - A, B: Integers to add
   - P: Modulus (defaults to secp256k1 field prime)

   RETURNS:
   Integer in range [0, p-1]"
  (declare (type integer a b p)
           (optimize (speed 3) (safety 1)))
  (mod (+ a b) p))

(defun mod-sub (a b &optional (p +secp256k1-p+))
  "Modular subtraction: (a - b) mod p.

   PARAMETERS:
   - A, B: Integers
   - P: Modulus (defaults to secp256k1 field prime)

   RETURNS:
   Integer in range [0, p-1]"
  (declare (type integer a b p)
           (optimize (speed 3) (safety 1)))
  (mod (- a b) p))

(defun mod-mul (a b &optional (p +secp256k1-p+))
  "Modular multiplication: (a * b) mod p.

   PARAMETERS:
   - A, B: Integers to multiply
   - P: Modulus (defaults to secp256k1 field prime)

   RETURNS:
   Integer in range [0, p-1]"
  (declare (type integer a b p)
           (optimize (speed 3) (safety 1)))
  (mod (* a b) p))

(defun mod-inverse (a &optional (n +secp256k1-p+))
  "Compute modular multiplicative inverse using extended Euclidean algorithm.

   Finds x such that (a * x) mod n = 1.

   PARAMETERS:
   - A: Integer to invert (must be coprime to N)
   - N: Modulus (defaults to secp256k1 field prime)

   RETURNS:
   Integer x in range [0, n-1] such that a*x = 1 (mod n)

   SIGNALS ERROR:
   If A and N are not coprime (GCD != 1)"
  (declare (type integer a n)
           (optimize (speed 3) (safety 1)))
  (let ((t0 0) (t1 1)
        (r0 n) (r1 (mod a n)))
    (loop while (not (zerop r1))
          do (let ((q (floor r0 r1)))
               (psetf t0 t1 t1 (- t0 (* q t1)))
               (psetf r0 r1 r1 (- r0 (* q r1)))))
    (when (> r0 1)
      (error "~A has no modular inverse mod ~A" a n))
    (if (< t0 0)
        (+ t0 n)
        t0)))

(defun mod-expt (base exp &optional (mod +secp256k1-p+))
  "Modular exponentiation using square-and-multiply algorithm.

   Computes base^exp mod mod efficiently.

   PARAMETERS:
   - BASE: Base integer
   - EXP: Non-negative exponent
   - MOD: Modulus (defaults to secp256k1 field prime)

   RETURNS:
   Integer in range [0, mod-1]"
  (declare (type integer base exp mod)
           (optimize (speed 3) (safety 1)))
  (let ((result 1))
    (setf base (mod base mod))
    (loop while (plusp exp)
          do (when (oddp exp)
               (setf result (mod (* result base) mod)))
             (setf exp (ash exp -1))
             (setf base (mod (* base base) mod)))
    result))

(defun mod-sqrt (n &optional (p +secp256k1-p+))
  "Compute modular square root for secp256k1 field.

   For secp256k1, p = 3 (mod 4), so we can use the simple formula:
   sqrt(n) = n^((p+1)/4) mod p

   PARAMETERS:
   - N: Integer whose square root to compute
   - P: Field prime (defaults to secp256k1 field prime)

   RETURNS:
   Square root of N mod P, or NIL if N is not a quadratic residue

   NOTE:
   Only works for primes p where p = 3 (mod 4), which includes secp256k1."
  (declare (type integer n p)
           (optimize (speed 3) (safety 1)))
  ;; For p ≡ 3 (mod 4), sqrt = n^((p+1)/4)
  (let ((y (mod-expt n (ash (1+ p) -2) p)))
    ;; Verify result
    (if (= (mod (* y y) p) (mod n p))
        y
        nil)))
