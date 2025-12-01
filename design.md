# ATM-Bank System Design Document

## Protocol Overview

Our ATM-Bank system implements a secure communication protocol designed to protect against an active network adversary who controls the router and can inspect, modify, drop, duplicate, or create packets. The system consists of three main components: an ATM, a Bank, and an initialization program that establishes shared cryptographic keys.

The protocol ensures confidentiality through AES-256-CBC encryption, integrity and authenticity through HMAC-SHA256, and replay protection through sequence numbers. All communications between the ATM and Bank are routed through a potentially malicious router, making the cryptographic protections essential for security.

## System Components

### Initialization Program
The `init` program creates two identical files containing shared cryptographic secrets: `<filename>.bank` and `<filename>.atm`. Each file contains:
- **Encryption Key** (32 bytes): AES-256 key for message encryption
- **HMAC Key** (32 bytes): HMAC-SHA256 key for message authentication  
- **Initial Nonce** (8 bytes): Starting value for sequence number generation

These keys are generated using OpenSSL's cryptographically secure random number generator and must be present before the Bank and ATM can communicate.

### Implementation Notes

- Sequence numbers start from the initial nonce value in the init files
- Each side maintains its own sequence counter
- Sequence numbers are checked to prevent replay attacks
- Failed HMAC verification results in message rejection
- All cryptographic operations use OpenSSL

### Bank Program
The Bank maintains user accounts in memory using a linked list structure and processes authentication, balance queries, and withdrawal requests from the ATM. It supports three local administrative commands:
- `create-user <name> <pin> <balance>`: Creates a new user and generates an encrypted `.card` file
- `deposit <name> <amount>`: Adds funds to an existing user's account
- `balance <name>`: Displays a user's current balance

When creating a user, the Bank generates an encrypted card file containing the username encrypted with AES-256-CBC, which the ATM must present during authentication. The Bank performs input validation on all commands and includes overflow protection for account balances.

### ATM Program
The ATM reads encrypted card files and prompts users for PINs before establishing sessions with the Bank. It supports four main operations:
- `begin-session <username>`: Reads card file, prompts for PIN, authenticates with Bank
- `withdraw <amount>`: Requests withdrawal from current user's account
- `balance`: Queries current user's account balance
- `end-session`: Logs out current user and clears session state

The ATM validates user input locally (usernames must be alphabetic, PINs must be 4 digits, amounts must be numeric) and encrypts all communications with the Bank. It maintains session state to ensure users must authenticate before performing transactions. Card file decryption uses the same AES-256-CBC encryption key shared with the Bank.

## File Formats

### Initialization Files (.bank and .atm)
Both files contain identical binary data (72 bytes total) structured as:
```c
typedef struct {
    uint8_t encryption_key[32];    // AES-256 key (32 bytes)
    uint8_t hmac_key[32];          // HMAC-SHA256 key (32 bytes)
    uint8_t initial_nonce[8];      // Starting sequence number (8 bytes)
} init_data_t;
```

The binary layout is:
```
[Encryption Key (32 bytes)][HMAC Key (32 bytes)][Initial Nonce (8 bytes)]
```

These keys are generated using `RAND_bytes()` from OpenSSL's cryptographically secure random number generator. Both the ATM and Bank must load the same initialization data to establish their shared cryptographic keys.

### Card Files (.card)
Card files are created by the Bank during user creation and contain the following binary structure:
```
[IV (16 bytes)][Ciphertext Length (4 bytes)][Encrypted Username (variable)]
```

- **IV** (16 bytes): Random initialization vector generated with `RAND_bytes()` for AES-256-CBC
- **Ciphertext Length** (4 bytes): Integer length of the encrypted username data (stored as `sizeof(int)`)
- **Encrypted Username** (variable): Username encrypted using AES-256-CBC with the Bank's encryption key

The card file format prevents unauthorized card creation since only the Bank possesses the encryption key needed to create valid cards. The ATM verifies authenticity by decrypting the username and comparing it to the requested username during `begin-session`.

## Message Protocol

### Wire Format
All messages between ATM and Bank use the following structure:
```
[IV (16 bytes)][Sequence Number (8 bytes)][Encrypted Data (variable)][HMAC (32 bytes)]
```

- **IV**: Fresh random initialization vector for each message using `RAND_bytes()`
- **Sequence Number**: 64-bit counter in network byte order (using host_to_network_64)
- **Encrypted Data**: AES-256-CBC encrypted plaintext message
- **HMAC**: SHA256 hash computed over IV, sequence number, and encrypted data
- **Total overhead**: 56 bytes (16 + 8 + 32) plus padding for AES block alignment

### Message Types
The protocol supports three primary message exchanges using simple text-based commands:

**Authentication (AUTH)**
- ATM sends: `AUTH <username> <pin>`
- Bank responds: `AUTH_OK` (successful) or `AUTH_FAIL` (failed)

**Balance Query (BALANCE)**
- ATM sends: `BALANCE <username>`
- Bank responds: `BALANCE <amount>` (successful) or `BALANCE_FAIL` (user not found)

**Withdrawal (WITHDRAW)**
- ATM sends: `WITHDRAW <username> <amount>`
- Bank responds: `WITHDRAW_OK` (successful) or `WITHDRAW_FAIL` (insufficient funds or user not found)

All messages are encrypted inside the secure wire format described above. The Bank increments the sequence number for each response (received_seq + 1) to maintain proper ordering.

## Security Analysis

### Attack 1: Message Confidentiality
**Threat**: An attacker controlling the router could intercept and read messages containing sensitive information like PINs, usernames, and account balances.

**Countermeasure**: All messages are encrypted using AES-256-CBC with a fresh random IV for each message. The encryption key is only known to the legitimate ATM and Bank, preventing the router from decrypting message contents.

**Implementation**: The `crypto_encrypt_and_auth` function generates a random IV and encrypts the plaintext using the shared encryption key before transmission.

### Attack 2: Message Tampering
**Threat**: An attacker could modify messages in transit to change withdrawal amounts, usernames, or other critical data.

**Countermeasure**: Every message includes an HMAC-SHA256 computed over the IV, sequence number, and encrypted data using a shared authentication key. Any modification will cause HMAC verification to fail.

**Implementation**: Messages are rejected if HMAC verification fails in `crypto_decrypt_and_verify`, ensuring that only authentic messages are processed.

### Attack 3: Replay Attacks
**Threat**: An attacker could capture and replay valid messages to repeat transactions or authentication attempts.

**Countermeasure**: Each message includes a sequence number that must be strictly increasing. Both ATM and Bank maintain sequence counters and reject messages with sequence numbers that are too low or have been seen before.

**Implementation**: The Bank checks `received_seq <= bank->last_sequence` and ignores replayed messages. The ATM increments its sequence number for each outbound message.

### Attack 4: Unauthorized Card Creation
**Threat**: An attacker could create fake card files to impersonate legitimate users.

**Countermeasure**: Card files contain usernames encrypted with the Bank's secret key. Since only the Bank possesses this key, attackers cannot create valid card files that will decrypt to legitimate usernames.

**Implementation**: During authentication, the ATM decrypts the card file using its copy of the Bank's encryption key and verifies the decrypted username matches the requested username.

### Attack 5: Man-in-the-Middle Authentication Bypass
**Threat**: An attacker could attempt to authenticate without knowing the correct PIN by manipulating the authentication protocol.

**Countermeasure**: The ATM sends both username and PIN to the Bank in encrypted form. The Bank verifies both the username exists and the PIN matches before sending an authentication success response. All messages are protected by HMAC to prevent modification.

**Implementation**: The Bank performs database lookup in `find_user` and compares the received PIN with the stored PIN using `strcmp` before responding with `AUTH_OK`.

## Limitations and Unaddressed Threats

While our protocol addresses the primary network-based attacks, several threats remain outside our scope:

1. **Physical Security**: We do not protect against physical access to the ATM or Bank computers, including memory inspection or key extraction through hardware attacks.

2. **Denial of Service**: An attacker controlling the router could simply drop all packets, preventing legitimate communication. Our protocol detects but cannot prevent this attack.

3. **Traffic Analysis**: While message contents are encrypted, an attacker could potentially infer information from message timing, frequency, or size patterns.

4. **Key Compromise**: If the initialization files are compromised, the entire security model fails. We assume these files are distributed and stored securely.

5. **Forward Secrecy**: Our protocol does not provide forward secrecy - compromise of long-term keys allows decryption of all past communications.
