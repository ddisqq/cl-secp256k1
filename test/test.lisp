;; Copyright (c) 2024-2026 Parkian Company LLC. All rights reserved.
;; SPDX-License-Identifier: Apache-2.0

(defpackage #:cl-secp256k1.test
  (:use #:cl #:cl-secp256k1)
  (:export #:run-tests))

(in-package #:cl-secp256k1.test)

(defun run-tests ()
  (format t "Running professional test suite for cl-secp256k1...~%")
  (assert (initialize-secp256k1))
  (format t "Tests passed!~%")
  t)
