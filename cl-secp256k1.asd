(asdf:defsystem #:cl-secp256k1
  :depends-on (#:alexandria #:bordeaux-threads)
  :components ((:module "src"
                :components ((:file "package")
                             (:file "cl-secp256k1" :depends-on ("package"))))))