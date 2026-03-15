;; Copyright (c) 2024-2026 Parkian Company LLC. All rights reserved.
;; SPDX-License-Identifier: Apache-2.0

(in-package #:cl-secp256k1)

;;; Core types for cl-secp256k1
(deftype cl-secp256k1-id () '(unsigned-byte 64))
(deftype cl-secp256k1-status () '(member :ready :active :error :shutdown))
