data "st-utilities_chacha20_encrypt" "encrypt" {
  encrypt_key  = "my-secret-passphrase"
  string_value = jsonencode({ foo = "bar" })
}

output "encrypted" {
  value = data.st-utilities_chacha20_encrypt.encrypt.encrypted_string_value
}
