;;;; Copyright (c) 2024-2026 Parkian Company LLC. All rights reserved.
;;;; SPDX-License-Identifier: BSD-3-Clause
;;;; This file is part of cl-secp256k1.

(defsystem "cl-secp256k1"
  :name "cl-secp256k1"
  :version "1.0.0"
  :author "Parkian Company LLC"
  :license "BSD-3-Clause"
  :description "Pure Common Lisp secp256k1 ECDSA implementation with zero external dependencies"
  :long-description "Complete implementation of secp256k1 elliptic curve cryptography
including ECDSA signing/verification with RFC 6979 deterministic nonces.
Suitable for Bitcoin and other cryptocurrency applications."
  :depends-on ()
  :serial t
  :components ((:file "package")
               (:module "src"
                :serial t
                :components ((:file "util")
                             (:file "field")
                             (:file "point")
                             (:file "rfc6979")
                             (:file "ecdsa"))))
  :in-order-to ((test-op (test-op "cl-secp256k1/test"))))

(defsystem "cl-secp256k1/test"
  :name "cl-secp256k1-test"
  :version "1.0.0"
  :author "Parkian Company LLC"
  :license "BSD-3-Clause"
  :description "Test suite for cl-secp256k1"
  :depends-on ("cl-secp256k1")
  :serial t
  :components ((:module "test"
                :components ((:file "test-ecdsa"))))
  :perform (test-op (op c)
             (symbol-call :cl-secp256k1.test :run-tests)))
