import Config

config :symmetric_encryption, :ciphers, [
  [
    version: 1,
    cipher_name: :aes_256_cbc,
    key: "cnBEPEe4XHQgyFYPUXgCCf/sTIszohxRO9x3KUJM9R8=",
    iv: "kVQJ+KQcamiaEQdQaKPjTg"
  ]
]

import_config "#{Mix.env()}.exs"
