# ATM-Bank Protocol Design

## Overview

This document describes the secure communication protocol between the ATM and Bank systems. The protocol is designed to protect against an active attacker who controls the router and can inspect, modify, drop, duplicate, or create packets.

## Initialization Files

The `init` program creates two files:
- `<filename>.bank` - Contains cryptographic keys for the bank
- `<filename>.atm` - Contains cryptographic keys for the ATM

Both files contain the same data structure (`init_data_t`):
- **Encryption Key** (32 bytes): AES-256 key for encrypting messages
- **HMAC Key** (32 bytes): HMAC-SHA256 key for message authentication
- **Initial Nonce** (8 bytes): Starting point for sequence numbers

These keys are generated using OpenSSL's cryptographically secure random number generator.

## Message Format

All messages between ATM and Bank are encrypted and authenticated. The wire format is:

```
[IV (16 bytes)][Sequence Number (8 bytes)][Encrypted Data (variable)][HMAC (32 bytes)]
```

### Components:

1. **IV (Initialization Vector)**: 16-byte random IV for AES-256-CBC encryption. Generated fresh for each message.

2. **Sequence Number**: 64-bit counter in network byte order, incremented for each message. Prevents replay attacks.

3. **Encrypted Data**: The actual protocol message, encrypted using AES-256-CBC with the encryption key.

4. **HMAC**: 32-byte HMAC-SHA256 computed over: `IV || Sequence Number || Encrypted Data`

### Plaintext Message Structure

Inside the encrypted data, messages follow this structure:

```c
typedef struct {
    message_type_t type;      // Message type (1 byte)
    uint64_t sequence;        // Sequence number (8 bytes, redundant but included for clarity)
    uint32_t data_len;        // Length of data payload (4 bytes)
    char data[];              // Variable-length data
} protocol_message_t;
```

## Message Types

- `MSG_AUTH_REQUEST` (1): ATM requests user authentication (begin-session)
- `MSG_AUTH_RESPONSE` (2): Bank responds to authentication request
- `MSG_BALANCE_REQUEST` (3): ATM requests account balance
- `MSG_BALANCE_RESPONSE` (4): Bank responds with balance
- `MSG_WITHDRAW_REQUEST` (5): ATM requests withdrawal
- `MSG_WITHDRAW_RESPONSE` (6): Bank responds to withdrawal
- `MSG_ERROR` (7): Error message

## Security Properties

### 1. Confidentiality
- All messages are encrypted using AES-256-CBC
- Each message uses a fresh random IV
- The router cannot read message contents

### 2. Integrity and Authentication
- HMAC-SHA256 ensures messages cannot be modified without detection
- HMAC is computed over IV, sequence number, and encrypted data
- Any tampering will cause HMAC verification to fail

### 3. Replay Protection
- Each message includes a sequence number
- Sequence numbers must be strictly increasing
- Replayed messages will be rejected (sequence number too low or already seen)

### 4. Entity Authentication
- Only entities with the shared keys (from init files) can create valid messages
- The bank and ATM verify each message's HMAC to ensure it came from the other party

## Protocol Flow

### Authentication (begin-session)
1. User inserts card and enters PIN at ATM
2. ATM reads card file and validates PIN locally (or sends to bank)
3. ATM sends `MSG_AUTH_REQUEST` with username and PIN (encrypted)
4. Bank verifies credentials and responds with `MSG_AUTH_RESPONSE`
5. If successful, ATM allows user to proceed

### Balance Query
1. ATM sends `MSG_BALANCE_REQUEST` with username
2. Bank looks up balance and sends `MSG_BALANCE_RESPONSE` with amount
3. ATM displays balance to user

### Withdrawal
1. ATM sends `MSG_WITHDRAW_REQUEST` with username and amount
2. Bank checks balance and processes withdrawal
3. Bank sends `MSG_WITHDRAW_RESPONSE` with success/failure
4. ATM dispenses cash if successful

## Implementation Notes

- Sequence numbers start from the initial nonce value in the init files
- Each side maintains its own sequence counter
- Sequence numbers are checked to prevent replay attacks
- Failed HMAC verification results in message rejection
- All cryptographic operations use OpenSSL

## Card File Format

Card files (`.card`) are created by the bank when a user is created. The format is protocol-specific and should contain:
- User identification information
- Encrypted PIN or PIN hash
- Possibly a card-specific secret for additional authentication

The exact format is part of the protocol implementation.

