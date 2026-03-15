;;;; Copyright (c) 2024-2026 Parkian Company LLC. All rights reserved.
;;;; SPDX-License-Identifier: BSD-3-Clause
;;;; This file is part of cl-secp256k1.

(asdf:defsystem #:"cl-secp256k1"
  :name "cl-secp256k1"
  :version "0.1.0"
  :author "Park Ian Co"
  :license "Apache-2.0"
  :description "Pure Common Lisp secp256k1 ECDSA implementation with zero external dependencies"
  :long-description "Complete implementation of secp256k1 elliptic curve cryptography
including ECDSA signing/verification with RFC 6979 deterministic nonces.
Suitable for Bitcoin and other cryptocurrency applications."
  :depends-on ()
  :serial t
  :components ((:file "package")
               (:module "src"
                :components ((:file "package")
                             (:file "conditions" :depends-on ("package"))
                             (:file "types" :depends-on ("package"))
                             (:file "cl-secp256k1" :depends-on ("package" "conditions" "types"))))))
  :in-order-to ((asdf:test-op (test-op "cl-secp256k1/test"))))

(asdf:defsystem #:"cl-secp256k1/test"
  :name "cl-secp256k1"
  :version "0.1.0"
  :author "Park Ian Co"
  :license "Apache-2.0"
  :description "Test suite for cl-secp256k1"
  :depends-on ("cl-secp256k1")
  :serial t
  :components ((:module "test"
                :components ((:file "test-ecdsa"))))
  :perform (asdf:test-op (op c)
             (let ((result (uiop:symbol-call :cl-secp256k1.test :run-tests)))
               (unless result
                 (error "Tests failed")))))
