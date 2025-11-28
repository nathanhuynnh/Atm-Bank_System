/*
 * Cryptographic utility functions for ATM-Bank protocol
 *
 * Provides encryption, decryption, and HMAC functions using OpenSSL
 */

#ifndef __CRYPTO_H__
#define __CRYPTO_H__

#include <stdint.h>
#include <stddef.h>
#include "../protocol.h"

// Initialize crypto context with keys from init file
// Returns 0 on success, -1 on error
int crypto_init(const char *init_file, uint8_t *enc_key, uint8_t *hmac_key);

// Encrypt and authenticate a message
// plaintext: input message to encrypt
// plaintext_len: length of plaintext
// ciphertext: output buffer (must be at least plaintext_len + IV_SIZE + HMAC_SIZE + NONCE_SIZE)
// sequence: sequence number for replay protection
// enc_key: encryption key
// hmac_key: HMAC key
// Returns length of ciphertext on success, -1 on error
int crypto_encrypt_and_auth(
    const uint8_t *plaintext, size_t plaintext_len,
    uint8_t *ciphertext, size_t ciphertext_max_len,
    uint64_t sequence,
    const uint8_t *enc_key, const uint8_t *hmac_key);

// Decrypt and verify a message
// ciphertext: encrypted message to decrypt
// ciphertext_len: length of ciphertext
// plaintext: output buffer (must be at least ciphertext_len - IV_SIZE - HMAC_SIZE - NONCE_SIZE)
// expected_sequence: expected sequence number (for replay protection)
// enc_key: encryption key
// hmac_key: HMAC key
// Returns length of plaintext on success, -1 on error (including authentication failure)
int crypto_decrypt_and_verify(
    const uint8_t *ciphertext, size_t ciphertext_len,
    uint8_t *plaintext, size_t plaintext_max_len,
    uint64_t *received_sequence,
    const uint8_t *enc_key, const uint8_t *hmac_key);

#endif

