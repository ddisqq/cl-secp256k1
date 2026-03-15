;;;; Copyright (c) 2024-2026 Parkian Company LLC. All rights reserved.
;;;; SPDX-License-Identifier: Apache-2.0
;;;; This file is part of cl-secp256k1.

;;;; Elliptic curve point operations for secp256k1

(in-package #:cl-secp256k1)

;;; ============================================================================
;;; Point Representation
;;; ============================================================================
;;;
;;; Points are represented as cons cells (x . y) where x and y are integers.
;;; The point at infinity (identity element) is represented as :INFINITY.
;;;
;;; The secp256k1 curve equation is: y^2 = x^3 + 7 (mod p)

;;; ============================================================================
;;; Point Predicates and Constructors
;;; ============================================================================

(defun point-at-infinity-p (point)
  "Check if POINT is the point at infinity (identity element).

   The point at infinity is the identity element for elliptic curve addition:
   P + O = P for any point P."
  (eq point :infinity))

(defun generator-point ()
  "Return the generator point G for secp256k1.

   G is the standard base point used for key generation.
   Public key = private_key * G"
  (cons +secp256k1-gx+ +secp256k1-gy+))

(defun valid-point-p (point)
  "Check if POINT is a valid point on the secp256k1 curve.

   Validates that:
   1. Point is the infinity point, OR
   2. Point satisfies the curve equation y^2 = x^3 + 7 (mod p)

   PARAMETERS:
   - POINT: A point (x . y) or :INFINITY

   RETURNS:
   T if point is valid, NIL otherwise"
  (if (point-at-infinity-p point)
      t
      (and (consp point)
           (integerp (car point))
           (integerp (cdr point))
           (let* ((x (car point))
                  (y (cdr point))
                  (p +secp256k1-p+))
             ;; Check 0 <= x, y < p
             (and (>= x 0) (< x p)
                  (>= y 0) (< y p)
                  ;; Check y^2 = x^3 + 7 mod p
                  (= (mod (* y y) p)
                     (mod (+ (* x x x) 7) p)))))))

;;; ============================================================================
;;; Point Arithmetic
;;; ============================================================================

(defun point-negate (point)
  "Negate a point: return -P such that P + (-P) = O.

   For elliptic curves, -P has the same x coordinate but negated y.

   PARAMETERS:
   - POINT: A point (x . y) or :INFINITY

   RETURNS:
   The negated point"
  (if (point-at-infinity-p point)
      :infinity
      (cons (car point)
            (mod (- +secp256k1-p+ (cdr point)) +secp256k1-p+))))

(defun point-double (point)
  "Double a point on secp256k1: compute 2P.

   Uses the tangent line at P to find the intersection with the curve.

   PARAMETERS:
   - POINT: A point (x . y) or :INFINITY

   RETURNS:
   The doubled point 2P

   FORMULA:
   s = (3*x^2) / (2*y) mod p
   x' = s^2 - 2*x mod p
   y' = s*(x - x') - y mod p"
  (declare (optimize (speed 3) (safety 1)))
  (when (point-at-infinity-p point)
    (return-from point-double :infinity))
  (let* ((x (car point))
         (y (cdr point))
         (p +secp256k1-p+))
    ;; If y = 0, tangent is vertical, result is infinity
    (when (zerop y)
      (return-from point-double :infinity))
    ;; s = (3*x^2) / (2*y) mod p
    (let* ((s (mod-mul
               (mod-mul 3 (mod-mul x x p) p)
               (mod-inverse (mod-mul 2 y p) p)
               p))
           ;; x' = s^2 - 2*x mod p
           (x3 (mod-sub (mod-mul s s p)
                        (mod-mul 2 x p)
                        p))
           ;; y' = s*(x - x') - y mod p
           (y3 (mod-sub (mod-mul s (mod-sub x x3 p) p)
                        y
                        p)))
      (cons x3 y3))))

(defun point-add (p1 p2)
  "Add two points on secp256k1: compute P1 + P2.

   PARAMETERS:
   - P1, P2: Points to add

   RETURNS:
   The sum P1 + P2

   FORMULA (for distinct points):
   s = (y2 - y1) / (x2 - x1) mod p
   x3 = s^2 - x1 - x2 mod p
   y3 = s*(x1 - x3) - y1 mod p"
  (declare (optimize (speed 3) (safety 1)))
  ;; Handle identity element
  (when (point-at-infinity-p p1)
    (return-from point-add p2))
  (when (point-at-infinity-p p2)
    (return-from point-add p1))
  (let* ((x1 (car p1)) (y1 (cdr p1))
         (x2 (car p2)) (y2 (cdr p2))
         (p +secp256k1-p+))
    ;; Same point - use doubling
    (when (and (= x1 x2) (= y1 y2))
      (return-from point-add (point-double p1)))
    ;; Points are inverses of each other: P + (-P) = O
    (when (and (= x1 x2) (= y1 (mod (- p y2) p)))
      (return-from point-add :infinity))
    ;; General case: distinct points with different x coordinates
    (let* ((s (mod-mul
               (mod-sub y2 y1 p)
               (mod-inverse (mod-sub x2 x1 p) p)
               p))
           ;; x3 = s^2 - x1 - x2 mod p
           (x3 (mod-sub
                (mod-sub (mod-mul s s p) x1 p)
                x2
                p))
           ;; y3 = s*(x1 - x3) - y1 mod p
           (y3 (mod-sub
                (mod-mul s (mod-sub x1 x3 p) p)
                y1
                p)))
      (cons x3 y3))))

(defun point-multiply (k point)
  "Scalar multiplication: compute k*P using double-and-add algorithm.

   This is the fundamental operation for ECDSA. Given a scalar k and
   point P, computes P + P + ... + P (k times).

   PARAMETERS:
   - K: Scalar multiplier (integer)
   - POINT: Base point

   RETURNS:
   The point k*P

   ALGORITHM:
   Double-and-add (binary method):
   For each bit of k from MSB to LSB:
     - Double the accumulator
     - If bit is 1, add the base point

   TIME COMPLEXITY: O(log k) point operations

   WARNING: This implementation is NOT constant-time and should not be
   used with secret scalars in adversarial environments."
  (declare (type integer k)
           (optimize (speed 3) (safety 1)))
  ;; Handle edge cases
  (when (or (zerop k) (point-at-infinity-p point))
    (return-from point-multiply :infinity))
  ;; Reduce k modulo the curve order
  (let ((result :infinity)
        (addend point)
        (n (mod k +secp256k1-n+)))
    (loop while (plusp n)
          do (when (oddp n)
               (setf result (point-add result addend)))
             (setf addend (point-double addend))
             (setf n (ash n -1)))
    result))
