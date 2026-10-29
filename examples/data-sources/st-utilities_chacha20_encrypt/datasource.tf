data "st-utilities_chacha20_encrypt" "encrypt" {
  string_value = jsonencode({ foo = "bar" })
  encrypt_key  = "my-secret-passphrase"
}

output "encrypted" {
  value = data.st-utilities_chacha20_encrypt.encrypt.encrypted_string_value
}
