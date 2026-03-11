;;;; Copyright (c) 2024-2026 Parkian Company LLC. All rights reserved.
;;;; SPDX-License-Identifier: BSD-3-Clause
;;;; This file is part of cl-secp256k1.

;;;; Test suite for cl-secp256k1

(in-package #:cl-secp256k1.test)

;;; ============================================================================
;;; Test Utilities
;;; ============================================================================

(defvar *test-count* 0)
(defvar *pass-count* 0)
(defvar *fail-count* 0)

(defun reset-test-counts ()
  (setf *test-count* 0
        *pass-count* 0
        *fail-count* 0))

(defmacro test-case (name &body body)
  "Define a test case."
  `(progn
     (incf *test-count*)
     (handler-case
         (progn
           ,@body
           (incf *pass-count*)
           (format t "  PASS: ~A~%" ,name))
       (error (e)
         (incf *fail-count*)
         (format t "  FAIL: ~A~%        ~A~%" ,name e)))))

(defun assert-equal (expected actual &optional message)
  (unless (equal expected actual)
    (error "~@[~A: ~]expected ~S but got ~S" message expected actual)))

(defun assert-true (value &optional message)
  (unless value
    (error "~@[~A: ~]expected true but got ~S" message value)))

(defun assert-nil (value &optional message)
  (when value
    (error "~@[~A: ~]expected nil but got ~S" message value)))

;;; ============================================================================
;;; Test Vectors
;;; ============================================================================

;; Known test vector for SHA-256
;; SHA256("abc") = ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad
(defvar +sha256-test-vector+
  #(#xba #x78 #x16 #xbf #x8f #x01 #xcf #xea
    #x41 #x41 #x40 #xde #x5d #xae #x22 #x23
    #xb0 #x03 #x61 #xa3 #x96 #x17 #x7a #x9c
    #xb4 #x10 #xff #x61 #xf2 #x00 #x15 #xad))

;; Known private key for testing (DO NOT USE IN PRODUCTION)
(defvar +test-private-key+
  #x0000000000000000000000000000000000000000000000000000000000000001)

;; Corresponding public key (1 * G)
(defvar +test-public-key-x+ +secp256k1-gx+)
(defvar +test-public-key-y+ +secp256k1-gy+)

;;; ============================================================================
;;; Hash Function Tests
;;; ============================================================================

(defun test-sha256 ()
  (format t "~%Testing SHA-256...~%")

  (test-case "SHA256 empty string"
    (let ((hash (sha256 #())))
      (assert-equal 32 (length hash))))

  (test-case "SHA256 'abc'"
    (let* ((input (map '(vector (unsigned-byte 8)) #'char-code "abc"))
           (hash (sha256 input)))
      (assert-equal (coerce +sha256-test-vector+ 'list)
                    (coerce hash 'list))))

  (test-case "SHA256d double hash"
    (let* ((input (map '(vector (unsigned-byte 8)) #'char-code "test"))
           (hash (sha256d input)))
      (assert-equal 32 (length hash)))))

;;; ============================================================================
;;; Field Arithmetic Tests
;;; ============================================================================

(defun test-field-arithmetic ()
  (format t "~%Testing field arithmetic...~%")

  (test-case "mod-add basic"
    (assert-equal 5 (mod-add 2 3 7))
    (assert-equal 0 (mod-add 4 3 7)))

  (test-case "mod-sub basic"
    (assert-equal 4 (mod-sub 6 2 7))
    (assert-equal 6 (mod-sub 2 3 7)))

  (test-case "mod-mul basic"
    (assert-equal 6 (mod-mul 2 3 7))
    (assert-equal 1 (mod-mul 4 2 7)))

  (test-case "mod-inverse"
    (let ((inv (mod-inverse 3 7)))
      ;; 3 * inv = 1 (mod 7)
      (assert-equal 1 (mod (* 3 inv) 7))))

  (test-case "mod-expt"
    (assert-equal 4 (mod-expt 2 2 7))
    (assert-equal 1 (mod-expt 2 3 7)))

  (test-case "mod-sqrt for secp256k1"
    (let* ((x 4)
           (sqrt-x (mod-sqrt x +secp256k1-p+)))
      (when sqrt-x
        (assert-equal (mod x +secp256k1-p+)
                      (mod (* sqrt-x sqrt-x) +secp256k1-p+))))))

;;; ============================================================================
;;; Point Operation Tests
;;; ============================================================================

(defun test-point-operations ()
  (format t "~%Testing point operations...~%")

  (test-case "generator-point is valid"
    (assert-true (valid-point-p (generator-point))))

  (test-case "point-at-infinity-p"
    (assert-true (point-at-infinity-p :infinity))
    (assert-nil (point-at-infinity-p (generator-point))))

  (test-case "point-add with infinity"
    (let ((g (generator-point)))
      (assert-equal g (point-add :infinity g))
      (assert-equal g (point-add g :infinity))))

  (test-case "point-double G"
    (let ((g2 (point-double (generator-point))))
      (assert-true (valid-point-p g2))))

  (test-case "point-multiply 1*G = G"
    (let ((result (point-multiply 1 (generator-point))))
      (assert-equal (generator-point) result)))

  (test-case "point-multiply 2*G = G+G"
    (let ((g (generator-point)))
      (assert-equal (point-add g g)
                    (point-multiply 2 g))))

  (test-case "point-negate"
    (let* ((g (generator-point))
           (neg-g (point-negate g))
           (sum (point-add g neg-g)))
      (assert-true (point-at-infinity-p sum)))))

;;; ============================================================================
;;; Key Generation Tests
;;; ============================================================================

(defun test-key-generation ()
  (format t "~%Testing key generation...~%")

  (test-case "valid-private-key-p"
    (assert-true (valid-private-key-p 1))
    (assert-true (valid-private-key-p (1- +secp256k1-n+)))
    (assert-nil (valid-private-key-p 0))
    (assert-nil (valid-private-key-p +secp256k1-n+)))

  (test-case "private-key-to-public with test key"
    (let ((pub (private-key-to-public +test-private-key+)))
      (assert-equal +test-public-key-x+ (car pub))
      (assert-equal +test-public-key-y+ (cdr pub))))

  (test-case "valid-public-key-p"
    (let ((pub (generator-point)))
      (assert-true (valid-public-key-p pub))))

  ;; Only run random key generation if /dev/urandom is available
  (handler-case
      (test-case "generate-private-key produces valid key"
        (let ((key (generate-private-key)))
          (assert-true (valid-private-key-p key))))
    (error ()
      (format t "  SKIP: generate-private-key (no secure random source)~%"))))

;;; ============================================================================
;;; Public Key Serialization Tests
;;; ============================================================================

(defun test-public-key-serialization ()
  (format t "~%Testing public key serialization...~%")

  (let ((pub (generator-point)))
    (test-case "compressed public key is 33 bytes"
      (let ((bytes (serialize-public-key pub :compressed t)))
        (assert-equal 33 (length bytes))
        (assert-true (or (= (aref bytes 0) #x02)
                         (= (aref bytes 0) #x03)))))

    (test-case "uncompressed public key is 65 bytes"
      (let ((bytes (serialize-public-key pub :compressed nil)))
        (assert-equal 65 (length bytes))
        (assert-equal #x04 (aref bytes 0))))

    (test-case "parse compressed public key roundtrip"
      (let* ((bytes (serialize-public-key pub :compressed t))
             (parsed (parse-public-key bytes)))
        (assert-equal (car pub) (car parsed))
        (assert-equal (cdr pub) (cdr parsed))))

    (test-case "parse uncompressed public key roundtrip"
      (let* ((bytes (serialize-public-key pub :compressed nil))
             (parsed (parse-public-key bytes)))
        (assert-equal pub parsed)))))

;;; ============================================================================
;;; ECDSA Tests
;;; ============================================================================

(defun test-ecdsa ()
  (format t "~%Testing ECDSA...~%")

  (let* ((private-key +test-private-key+)
         (public-key (private-key-to-public private-key))
         (message-hash (sha256 (map '(vector (unsigned-byte 8)) #'char-code "test message"))))

    (test-case "ecdsa-sign produces valid signature"
      (let ((sig (ecdsa-sign message-hash private-key)))
        (assert-true (consp sig))
        (assert-true (plusp (car sig)))
        (assert-true (< (car sig) +secp256k1-n+))
        (assert-true (plusp (cdr sig)))
        (assert-true (< (cdr sig) +secp256k1-n+))))

    (test-case "ecdsa-verify accepts valid signature"
      (let ((sig (ecdsa-sign message-hash private-key)))
        (assert-true (ecdsa-verify message-hash sig public-key))))

    (test-case "ecdsa-verify rejects wrong message"
      (let ((sig (ecdsa-sign message-hash private-key))
            (wrong-hash (sha256 (map '(vector (unsigned-byte 8)) #'char-code "wrong message"))))
        (assert-nil (ecdsa-verify wrong-hash sig public-key))))

    (test-case "ecdsa-verify rejects wrong public key"
      (let* ((sig (ecdsa-sign message-hash private-key))
             (wrong-pub (private-key-to-public 2)))
        (assert-nil (ecdsa-verify message-hash sig wrong-pub))))

    (test-case "signature has low-S (BIP-62)"
      (let ((sig (ecdsa-sign message-hash private-key)))
        ;; s should be <= n/2
        (assert-true (<= (cdr sig) (ash +secp256k1-n+ -1)))))

    (test-case "deterministic signatures (RFC 6979)"
      ;; Same message and key should produce same signature
      (let ((sig1 (ecdsa-sign message-hash private-key))
            (sig2 (ecdsa-sign message-hash private-key)))
        (assert-equal sig1 sig2)))))

;;; ============================================================================
;;; Signature Encoding Tests
;;; ============================================================================

(defun test-signature-encoding ()
  (format t "~%Testing signature encoding...~%")

  (let* ((r #x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef)
         (s #xfedcba0987654321fedcba0987654321fedcba0987654321fedcba0987654321))

    (test-case "DER encode/decode roundtrip"
      (let* ((der (der-encode-signature r s))
             (decoded (der-decode-signature der)))
        (assert-equal r (car decoded))
        (assert-equal s (cdr decoded))))

    (test-case "DER signature format"
      (let ((der (der-encode-signature r s)))
        ;; Should start with SEQUENCE tag
        (assert-equal #x30 (aref der 0))))

    (test-case "compact encode/decode roundtrip"
      (let* ((compact (compact-encode-signature r s))
             (decoded (compact-decode-signature compact)))
        (assert-equal 64 (length compact))
        (assert-equal r (car decoded))
        (assert-equal s (cdr decoded))))))

;;; ============================================================================
;;; Integration Tests
;;; ============================================================================

(defun test-integration ()
  (format t "~%Testing integration...~%")

  (test-case "full sign/verify flow"
    (let* ((private-key +test-private-key+)
           (public-key (private-key-to-public private-key))
           (message "Hello, secp256k1!")
           (hash (sha256 (map '(vector (unsigned-byte 8)) #'char-code message)))
           (signature (ecdsa-sign hash private-key)))
      (assert-true (ecdsa-verify hash signature public-key))
      ;; Serialize and parse public key, verify again
      (let* ((pub-bytes (serialize-public-key public-key :compressed t))
             (parsed-pub (parse-public-key pub-bytes)))
        (assert-true (ecdsa-verify hash signature parsed-pub))))))

;;; ============================================================================
;;; Test Runner
;;; ============================================================================

(defun run-tests ()
  "Run all tests and report results."
  (format t "~%========================================~%")
  (format t "cl-secp256k1 Test Suite~%")
  (format t "========================================~%")

  (reset-test-counts)

  (test-sha256)
  (test-field-arithmetic)
  (test-point-operations)
  (test-key-generation)
  (test-public-key-serialization)
  (test-ecdsa)
  (test-signature-encoding)
  (test-integration)

  (format t "~%========================================~%")
  (format t "Results: ~D passed, ~D failed, ~D total~%"
          *pass-count* *fail-count* *test-count*)
  (format t "========================================~%")

  (zerop *fail-count*))
