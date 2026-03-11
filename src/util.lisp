;;;; Copyright (c) 2024-2026 Parkian Company LLC. All rights reserved.
;;;; SPDX-License-Identifier: BSD-3-Clause
;;;; This file is part of cl-secp256k1.

;;;; Byte manipulation utilities and SHA-256 implementation for RFC 6979

(in-package #:cl-secp256k1)

;;; ============================================================================
;;; Byte Conversion Utilities
;;; ============================================================================

(defun bytes-to-integer (bytes &key (big-endian t))
  "Convert byte array to arbitrary-precision integer.

   PARAMETERS:
   - BYTES: Input byte array
   - BIG-ENDIAN: If T (default), interpret as MSB first

   RETURNS:
   Non-negative integer"
  (declare (type (simple-array (unsigned-byte 8) (*)) bytes)
           (type boolean big-endian)
           (optimize (speed 3) (safety 1)))
  (let ((result 0))
    (declare (type integer result))
    (if big-endian
        (loop for byte of-type (unsigned-byte 8) across bytes
              do (setf result (+ (ash result 8) byte)))
        (loop for i of-type fixnum from (1- (length bytes)) downto 0
              do (setf result (+ (ash result 8) (aref bytes i)))))
    result))

(defun integer-to-bytes (integer n-bytes &key (big-endian t))
  "Convert integer to byte array of specified length.

   PARAMETERS:
   - INTEGER: Non-negative integer to convert
   - N-BYTES: Output array length
   - BIG-ENDIAN: If T (default), output MSB first

   RETURNS:
   Byte array of length N-BYTES"
  (declare (type integer integer)
           (type fixnum n-bytes)
           (type boolean big-endian)
           (optimize (speed 3) (safety 1)))
  (let ((result (make-array n-bytes :element-type '(unsigned-byte 8) :initial-element 0)))
    (if big-endian
        (loop for i from (1- n-bytes) downto 0
              for j from 0
              do (setf (aref result j) (ldb (byte 8 (* i 8)) integer)))
        (loop for i from 0 below n-bytes
              do (setf (aref result i) (ldb (byte 8 (* i 8)) integer))))
    result))

(defun concatenate-bytes (&rest arrays)
  "Concatenate multiple byte arrays into one."
  (let* ((total-len (reduce #'+ arrays :key #'length))
         (result (make-array total-len :element-type '(unsigned-byte 8)))
         (pos 0))
    (dolist (arr arrays result)
      (replace result arr :start1 pos)
      (incf pos (length arr)))))

;;; ============================================================================
;;; SHA-256 Implementation (FIPS 180-4)
;;; ============================================================================

;; SHA-256 round constants
;; Using alexandria-style define-constant pattern for SBCL compatibility
(defvar +sha256-k+
  #(#x428a2f98 #x71374491 #xb5c0fbcf #xe9b5dba5
    #x3956c25b #x59f111f1 #x923f82a4 #xab1c5ed5
    #xd807aa98 #x12835b01 #x243185be #x550c7dc3
    #x72be5d74 #x80deb1fe #x9bdc06a7 #xc19bf174
    #xe49b69c1 #xefbe4786 #x0fc19dc6 #x240ca1cc
    #x2de92c6f #x4a7484aa #x5cb0a9dc #x76f988da
    #x983e5152 #xa831c66d #xb00327c8 #xbf597fc7
    #xc6e00bf3 #xd5a79147 #x06ca6351 #x14292967
    #x27b70a85 #x2e1b2138 #x4d2c6dfc #x53380d13
    #x650a7354 #x766a0abb #x81c2c92e #x92722c85
    #xa2bfe8a1 #xa81a664b #xc24b8b70 #xc76c51a3
    #xd192e819 #xd6990624 #xf40e3585 #x106aa070
    #x19a4c116 #x1e376c08 #x2748774c #x34b0bcb5
    #x391c0cb3 #x4ed8aa4a #x5b9cca4f #x682e6ff3
    #x748f82ee #x78a5636f #x84c87814 #x8cc70208
    #x90befffa #xa4506ceb #xbef9a3f7 #xc67178f2)
  "SHA-256 round constants (first 32 bits of fractional parts of cube roots of first 64 primes)")

(defmacro sha256-rotr (x n)
  "Right rotate 32-bit value X by N bits."
  `(logior (ldb (byte 32 0) (ash ,x (- ,n)))
           (ldb (byte 32 0) (ash ,x (- 32 ,n)))))

(defmacro sha256-ch (x y z)
  "SHA-256 Ch function: (x AND y) XOR ((NOT x) AND z)"
  `(logxor (logand ,x ,y) (logand (lognot ,x) ,z)))

(defmacro sha256-maj (x y z)
  "SHA-256 Maj function: (x AND y) XOR (x AND z) XOR (y AND z)"
  `(logxor (logand ,x ,y) (logand ,x ,z) (logand ,y ,z)))

(defmacro sha256-sigma0 (x)
  "SHA-256 big sigma 0"
  `(logxor (sha256-rotr ,x 2) (sha256-rotr ,x 13) (sha256-rotr ,x 22)))

(defmacro sha256-sigma1 (x)
  "SHA-256 big sigma 1"
  `(logxor (sha256-rotr ,x 6) (sha256-rotr ,x 11) (sha256-rotr ,x 25)))

(defmacro sha256-gamma0 (x)
  "SHA-256 small sigma 0"
  `(logxor (sha256-rotr ,x 7) (sha256-rotr ,x 18) (ash ,x -3)))

(defmacro sha256-gamma1 (x)
  "SHA-256 small sigma 1"
  `(logxor (sha256-rotr ,x 17) (sha256-rotr ,x 19) (ash ,x -10)))

(defun sha256 (data)
  "Compute SHA-256 hash of DATA (byte vector or string).
   Returns 32-byte hash digest.

   FIPS 180-4 compliant implementation."
  (let* ((data (if (stringp data)
                   (map '(vector (unsigned-byte 8)) #'char-code data)
                   (coerce data '(simple-array (unsigned-byte 8) (*)))))
         (len (length data))
         (bit-len (* len 8))
         (h (list #x6a09e667 #xbb67ae85 #x3c6ef372 #xa54ff53a
                  #x510e527f #x9b05688c #x1f83d9ab #x5be0cd19))
         (w (make-array 64 :element-type '(unsigned-byte 32))))

    ;; Pad message
    (let* ((pad-len (- 64 (mod (+ len 9) 64)))
           (total-len (+ len 1 pad-len 8))
           (padded (make-array total-len :element-type '(unsigned-byte 8) :initial-element 0)))
      (replace padded data)
      (setf (aref padded len) #x80)
      ;; Append length in bits (big-endian)
      (loop for i from 0 below 8
            do (setf (aref padded (- total-len 1 i))
                     (ldb (byte 8 (* i 8)) bit-len)))

      ;; Process 512-bit blocks
      (loop for block-start from 0 below total-len by 64
            do (progn
                 ;; Prepare message schedule
                 (loop for i from 0 below 16
                       do (setf (aref w i)
                                (logior (ash (aref padded (+ block-start (* i 4))) 24)
                                        (ash (aref padded (+ block-start (* i 4) 1)) 16)
                                        (ash (aref padded (+ block-start (* i 4) 2)) 8)
                                        (aref padded (+ block-start (* i 4) 3)))))
                 (loop for i from 16 below 64
                       do (setf (aref w i)
                                (ldb (byte 32 0)
                                     (+ (sha256-gamma1 (aref w (- i 2)))
                                        (aref w (- i 7))
                                        (sha256-gamma0 (aref w (- i 15)))
                                        (aref w (- i 16))))))

                 ;; Initialize working variables
                 (let ((a (nth 0 h)) (b (nth 1 h)) (c (nth 2 h)) (d (nth 3 h))
                       (e (nth 4 h)) (f (nth 5 h)) (g (nth 6 h)) (hh (nth 7 h)))
                   ;; Compression function
                   (loop for i from 0 below 64
                         do (let* ((s1 (sha256-sigma1 e))
                                   (ch (sha256-ch e f g))
                                   (temp1 (ldb (byte 32 0)
                                               (+ hh s1 ch (aref +sha256-k+ i) (aref w i))))
                                   (s0 (sha256-sigma0 a))
                                   (maj (sha256-maj a b c))
                                   (temp2 (ldb (byte 32 0) (+ s0 maj))))
                              (setf hh g
                                    g f
                                    f e
                                    e (ldb (byte 32 0) (+ d temp1))
                                    d c
                                    c b
                                    b a
                                    a (ldb (byte 32 0) (+ temp1 temp2)))))

                   ;; Add compressed chunk to hash value
                   (setf h (list (ldb (byte 32 0) (+ (nth 0 h) a))
                                 (ldb (byte 32 0) (+ (nth 1 h) b))
                                 (ldb (byte 32 0) (+ (nth 2 h) c))
                                 (ldb (byte 32 0) (+ (nth 3 h) d))
                                 (ldb (byte 32 0) (+ (nth 4 h) e))
                                 (ldb (byte 32 0) (+ (nth 5 h) f))
                                 (ldb (byte 32 0) (+ (nth 6 h) g))
                                 (ldb (byte 32 0) (+ (nth 7 h) hh))))))))

    ;; Produce final hash value (big-endian)
    (let ((result (make-array 32 :element-type '(unsigned-byte 8))))
      (loop for i from 0 below 8
            for val in h
            do (setf (aref result (* i 4)) (ldb (byte 8 24) val)
                     (aref result (+ (* i 4) 1)) (ldb (byte 8 16) val)
                     (aref result (+ (* i 4) 2)) (ldb (byte 8 8) val)
                     (aref result (+ (* i 4) 3)) (ldb (byte 8 0) val)))
      result)))

(defun sha256d (data)
  "Compute double SHA-256: SHA256(SHA256(data)).
   Standard hash for Bitcoin block hashes and transaction IDs."
  (sha256 (sha256 data)))

;;; ============================================================================
;;; HMAC-SHA256 (RFC 2104)
;;; ============================================================================

(defun hmac-sha256 (key message)
  "Compute HMAC-SHA256(key, message).
   Returns 32-byte authentication tag.

   Used by RFC 6979 for deterministic nonce generation."
  (let* ((key (if (stringp key)
                  (map '(vector (unsigned-byte 8)) #'char-code key)
                  (coerce key '(simple-array (unsigned-byte 8) (*)))))
         (message (if (stringp message)
                      (map '(vector (unsigned-byte 8)) #'char-code message)
                      (coerce message '(simple-array (unsigned-byte 8) (*)))))
         (block-size 64)
         (key-len (length key)))

    ;; If key > block-size, hash it
    (when (> key-len block-size)
      (setf key (sha256 key)))

    ;; Pad key to block size
    (when (< (length key) block-size)
      (let ((padded (make-array block-size :element-type '(unsigned-byte 8) :initial-element 0)))
        (replace padded key)
        (setf key padded)))

    ;; Compute HMAC: H((K XOR opad) || H((K XOR ipad) || message))
    (let ((o-key-pad (make-array block-size :element-type '(unsigned-byte 8)))
          (i-key-pad (make-array block-size :element-type '(unsigned-byte 8))))
      (loop for i from 0 below block-size
            do (setf (aref o-key-pad i) (logxor (aref key i) #x5c)
                     (aref i-key-pad i) (logxor (aref key i) #x36)))

      ;; Inner hash: H((K XOR ipad) || message)
      (let* ((inner-input (concatenate-bytes i-key-pad message))
             (inner-hash (sha256 inner-input))
             ;; Outer hash: H((K XOR opad) || inner-hash)
             (outer-input (concatenate-bytes o-key-pad inner-hash)))
        (sha256 outer-input)))))

;;; ============================================================================
;;; Random Number Generation
;;; ============================================================================

(defvar *random-state-lock* nil
  "Lock for thread-safe random number generation.")

(defun ensure-random-lock ()
  "Ensure the random state lock exists."
  (unless *random-state-lock*
    #+sbcl (setf *random-state-lock* (sb-thread:make-mutex :name "cl-secp256k1-random-lock"))
    #-sbcl (setf *random-state-lock* t)))

(defun random-bytes (n)
  "Generate N cryptographically secure random bytes.
   Uses /dev/urandom on Unix systems."
  (ensure-random-lock)
  (let ((result (make-array n :element-type '(unsigned-byte 8))))
    (handler-case
        (with-open-file (urandom "/dev/urandom" :element-type '(unsigned-byte 8))
          (read-sequence result urandom)
          result)
      (error ()
        ;; Fallback to Lisp's random (NOT cryptographically secure!)
        ;; Only for testing purposes
        (warn "Using non-cryptographic random source - NOT suitable for production!")
        (dotimes (i n)
          (setf (aref result i) (random 256)))
        result))))
