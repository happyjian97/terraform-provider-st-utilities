# Generate the secret key and nonce as ephemeral values so they are never
# written to state or plan files. Requires the random provider >= 3.7.0 and
# Terraform >= 1.11 (write-only arguments and ephemeral resources).
# The .hex outputs are only the transport encoding (random raw bytes cannot
# be a Terraform string): the provider hex-decodes them and uses the raw bytes
# they represent -- the 32-byte AES-256 key and the 12-byte GCM nonce.

resource "random_bytes" "key" {
  length = 32
}

ephemeral "random_bytes" "nonce" {
  length = 12
}

resource "st-utilities_aes256_gcm_encrypt" "encrypt" {
  secret_key   = random_bytes.key.hex
  nonce        = ephemeral.random_bytes.nonce.hex
  string_value = jsonencode({ foo = "bar" })
  version      = 1
}

output "encrypted" {
  value     = st-utilities_aes256_gcm_encrypt.encrypt.encrypted_string_output
  sensitive = true
}
