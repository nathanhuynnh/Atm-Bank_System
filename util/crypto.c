#include "crypto.h"
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/rand.h>
#include <openssl/crypto.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <arpa/inet.h>

// Helper functions for 64-bit byte order conversion
static uint64_t host_to_network_64(uint64_t host)
{
    // Check if we're on a big-endian system
    union {
        uint32_t i;
        uint8_t c[4];
    } test = {0x01020304};
    
    if (test.c[0] == 0x01)
    {
        // Big-endian: no conversion needed
        return host;
    }
    else
    {
        // Little-endian: swap bytes
        return ((uint64_t)htonl((uint32_t)(host >> 32)) << 32) | htonl((uint32_t)host);
    }
}

static uint64_t network_to_host_64(uint64_t net)
{
    // Same logic - network byte order is big-endian
    union {
        uint32_t i;
        uint8_t c[4];
    } test = {0x01020304};
    
    if (test.c[0] == 0x01)
    {
        // Big-endian: no conversion needed
        return net;
    }
    else
    {
        // Little-endian: swap bytes
        return ((uint64_t)ntohl((uint32_t)(net >> 32)) << 32) | ntohl((uint32_t)net);
    }
}

// Message format: [IV (16 bytes)][NONCE (8 bytes)][CIPHERTEXT (variable)][HMAC (32 bytes)]
// Total overhead: IV_SIZE + NONCE_SIZE + HMAC_SIZE = 16 + 8 + 32 = 56 bytes

int crypto_encrypt_and_auth(
    const uint8_t *plaintext, size_t plaintext_len,
    uint8_t *ciphertext, size_t ciphertext_max_len,
    uint64_t sequence,
    const uint8_t *enc_key, const uint8_t *hmac_key)
{
    EVP_CIPHER_CTX *ctx = NULL;
    int len = 0;
    int ciphertext_len = 0;
    uint8_t *iv = ciphertext;
    uint8_t *nonce = ciphertext + IV_SIZE;
    uint8_t *encrypted_data = ciphertext + IV_SIZE + NONCE_SIZE;
    uint8_t *hmac_output = NULL;
    size_t encrypted_len = 0;
    HMAC_CTX *hmac_ctx = NULL;
    unsigned int hmac_len = 0;
    int ret = -1;

    // Check buffer size
    if (ciphertext_max_len < plaintext_len + IV_SIZE + NONCE_SIZE + HMAC_SIZE)
    {
        return -1;
    }

    // Generate random IV
    if (RAND_bytes(iv, IV_SIZE) != 1)
    {
        return -1;
    }

    // Write sequence number (nonce) in network byte order
    uint64_t seq_net = host_to_network_64(sequence);
    memcpy(nonce, &seq_net, NONCE_SIZE);

    // Create and initialize cipher context
    ctx = EVP_CIPHER_CTX_new();
    if (ctx == NULL)
    {
        return -1;
    }

    // Initialize encryption operation
    if (EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, enc_key, iv) != 1)
    {
        goto cleanup;
    }

    // Encrypt plaintext
    if (EVP_EncryptUpdate(ctx, encrypted_data, &len, plaintext, plaintext_len) != 1)
    {
        goto cleanup;
    }
    encrypted_len = len;

    // Finalize encryption
    if (EVP_EncryptFinal_ex(ctx, encrypted_data + len, &len) != 1)
    {
        goto cleanup;
    }
    encrypted_len += len;

    // Calculate HMAC over: IV || NONCE || CIPHERTEXT
    hmac_output = ciphertext + IV_SIZE + NONCE_SIZE + encrypted_len;
    hmac_ctx = HMAC_CTX_new();
    if (hmac_ctx == NULL)
    {
        goto cleanup;
    }

    if (HMAC_Init_ex(hmac_ctx, hmac_key, HMAC_KEY_SIZE, EVP_sha256(), NULL) != 1)
    {
        goto cleanup;
    }

    // HMAC the IV
    if (HMAC_Update(hmac_ctx, iv, IV_SIZE) != 1)
    {
        goto cleanup;
    }

    // HMAC the nonce (sequence number)
    if (HMAC_Update(hmac_ctx, nonce, NONCE_SIZE) != 1)
    {
        goto cleanup;
    }

    // HMAC the encrypted data
    if (HMAC_Update(hmac_ctx, encrypted_data, encrypted_len) != 1)
    {
        goto cleanup;
    }

    // Finalize HMAC
    if (HMAC_Final(hmac_ctx, hmac_output, &hmac_len) != 1)
    {
        goto cleanup;
    }

    if (hmac_len != HMAC_SIZE)
    {
        goto cleanup;
    }

    ciphertext_len = IV_SIZE + NONCE_SIZE + encrypted_len + HMAC_SIZE;
    ret = ciphertext_len;

cleanup:
    if (ctx != NULL)
    {
        EVP_CIPHER_CTX_free(ctx);
    }
    if (hmac_ctx != NULL)
    {
        HMAC_CTX_free(hmac_ctx);
    }

    return ret;
}

int crypto_decrypt_and_verify(
    const uint8_t *ciphertext, size_t ciphertext_len,
    uint8_t *plaintext, size_t plaintext_max_len,
    uint64_t *received_sequence,
    const uint8_t *enc_key, const uint8_t *hmac_key)
{
    EVP_CIPHER_CTX *ctx = NULL;
    int len = 0;
    int plaintext_len = 0;
    const uint8_t *iv = ciphertext;
    const uint8_t *nonce = ciphertext + IV_SIZE;
    const uint8_t *encrypted_data = ciphertext + IV_SIZE + NONCE_SIZE;
    size_t encrypted_len = ciphertext_len - IV_SIZE - NONCE_SIZE - HMAC_SIZE;
    const uint8_t *hmac_received = ciphertext + IV_SIZE + NONCE_SIZE + encrypted_len;
    uint8_t hmac_calculated[HMAC_SIZE];
    HMAC_CTX *hmac_ctx = NULL;
    unsigned int hmac_len = 0;
    uint64_t seq_net;
    int ret = -1;

    // Check minimum size
    if (ciphertext_len < IV_SIZE + NONCE_SIZE + HMAC_SIZE)
    {
        return -1;
    }

    // Verify HMAC first (before decryption to prevent timing attacks on invalid messages)
    hmac_ctx = HMAC_CTX_new();
    if (hmac_ctx == NULL)
    {
        return -1;
    }

    if (HMAC_Init_ex(hmac_ctx, hmac_key, HMAC_KEY_SIZE, EVP_sha256(), NULL) != 1)
    {
        goto cleanup;
    }

    // HMAC the IV
    if (HMAC_Update(hmac_ctx, iv, IV_SIZE) != 1)
    {
        goto cleanup;
    }

    // HMAC the nonce
    if (HMAC_Update(hmac_ctx, nonce, NONCE_SIZE) != 1)
    {
        goto cleanup;
    }

    // HMAC the encrypted data
    if (HMAC_Update(hmac_ctx, encrypted_data, encrypted_len) != 1)
    {
        goto cleanup;
    }

    // Calculate HMAC
    if (HMAC_Final(hmac_ctx, hmac_calculated, &hmac_len) != 1)
    {
        goto cleanup;
    }

    if (hmac_len != HMAC_SIZE)
    {
        goto cleanup;
    }

    // Compare HMACs (constant-time comparison)
    if (CRYPTO_memcmp(hmac_received, hmac_calculated, HMAC_SIZE) != 0)
    {
        // HMAC verification failed - message was tampered with
        goto cleanup;
    }

    // Extract sequence number
    memcpy(&seq_net, nonce, NONCE_SIZE);
    *received_sequence = network_to_host_64(seq_net);

    // Create and initialize cipher context
    ctx = EVP_CIPHER_CTX_new();
    if (ctx == NULL)
    {
        goto cleanup;
    }

    // Initialize decryption operation
    if (EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, enc_key, iv) != 1)
    {
        goto cleanup;
    }

    // Decrypt ciphertext
    if (EVP_DecryptUpdate(ctx, plaintext, &len, encrypted_data, encrypted_len) != 1)
    {
        goto cleanup;
    }
    plaintext_len = len;

    // Finalize decryption
    if (EVP_DecryptFinal_ex(ctx, plaintext + len, &len) != 1)
    {
        goto cleanup;
    }
    plaintext_len += len;

    if (plaintext_len > plaintext_max_len)
    {
        goto cleanup;
    }

    ret = plaintext_len;

cleanup:
    if (ctx != NULL)
    {
        EVP_CIPHER_CTX_free(ctx);
    }
    if (hmac_ctx != NULL)
    {
        HMAC_CTX_free(hmac_ctx);
    }

    return ret;
}

