;; Copyright (c) 2024-2026 Parkian Company LLC. All rights reserved.
;; SPDX-License-Identifier: Apache-2.0

(defpackage #:cl-secp256k1.test
  (:use #:cl #:cl-secp256k1)
  (:export #:run-tests))

(in-package #:cl-secp256k1.test)

(defun run-tests ()
  (format t "Executing functional test suite for cl-secp256k1...~%")
  (assert (equal (deep-copy-list '(1 (2 3) 4)) '(1 (2 3) 4)))
  (assert (equal (group-by-count '(1 2 3 4 5) 2) '((1 2) (3 4) (5))))
  (format t "All functional tests passed!~%")
  t)
