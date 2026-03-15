;; Copyright (c) 2024-2026 Parkian Company LLC. All rights reserved.
;; SPDX-License-Identifier: Apache-2.0

(in-package #:cl-secp256k1)

(define-condition cl-secp256k1-error (error)
  ((message :initarg :message :reader cl-secp256k1-error-message))
  (:report (lambda (condition stream)
             (format stream "cl-secp256k1 error: ~A" (cl-secp256k1-error-message condition)))))
