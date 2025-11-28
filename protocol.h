/*
 * Protocol definitions for secure ATM-Bank communication
 *
 * This header defines the message format and cryptographic constants
 * used for secure communication between the ATM and Bank.
 */

#ifndef __PROTOCOL_H__
#define __PROTOCOL_H__

#include <stdint.h>

// Cryptographic constants
#define AES_KEY_SIZE 32          // 256 bits for AES-256
#define HMAC_KEY_SIZE 32         // 256 bits for HMAC-SHA256
#define IV_SIZE 16               // 128 bits for AES IV
#define HMAC_SIZE 32             // 256 bits for HMAC-SHA256 output
#define NONCE_SIZE 8             // 64 bits for nonce/sequence number

// Maximum message sizes
#define MAX_PLAINTEXT_SIZE 512
#define MAX_CIPHERTEXT_SIZE (MAX_PLAINTEXT_SIZE + IV_SIZE + HMAC_SIZE + NONCE_SIZE + 16)

// Message types
typedef enum {
    MSG_AUTH_REQUEST = 1,        // ATM requests authentication (begin-session)
    MSG_AUTH_RESPONSE = 2,        // Bank responds to authentication
    MSG_BALANCE_REQUEST = 3,      // ATM requests balance
    MSG_BALANCE_RESPONSE = 4,     // Bank responds with balance
    MSG_WITHDRAW_REQUEST = 5,     // ATM requests withdrawal
    MSG_WITHDRAW_RESPONSE = 6,    // Bank responds to withdrawal
    MSG_ERROR = 7                 // Error message
} message_type_t;

// Protocol message structure (for plaintext)
// Note: This is the logical structure; actual messages are encrypted
typedef struct {
    message_type_t type;
    uint64_t sequence;           // Sequence number to prevent replay attacks
    uint32_t data_len;           // Length of data payload
    char data[MAX_PLAINTEXT_SIZE]; // Variable-length data
} protocol_message_t;

// Init file structure (what gets stored in .bank and .atm files)
typedef struct {
    uint8_t encryption_key[AES_KEY_SIZE];
    uint8_t hmac_key[HMAC_KEY_SIZE];
    uint8_t initial_nonce[NONCE_SIZE];
} init_data_t;

#endif

