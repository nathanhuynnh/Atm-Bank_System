#include "atm.h"
#include "ports.h"
#include "../util/crypto.h"
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <ctype.h>
#include <limits.h>
#include <openssl/evp.h>

// Helper functions
static int is_valid_user(const char *name) {
    if (name == NULL || strlen(name) == 0 || strlen(name) > 250) return 0;
    for (int i = 0; name[i]; i++) {
        if (!isalpha((unsigned char)name[i])) return 0;
    }
    return 1;
}

static int is_valid_pin(const char *pin) {
    if (pin == NULL || strlen(pin) != 4) return 0;
    for (int i = 0; i < 4; i++) {
        if (!isdigit((unsigned char)pin[i])) return 0;
    }
    return 1;
}

static int is_valid_amount(const char *amt) {
    if (amt == NULL || strlen(amt) == 0) return 0;
    for (int i = 0; amt[i]; i++) {
        if (!isdigit((unsigned char)amt[i])) return 0;
    }
    return 1;
}

ATM* atm_create(const char *init_filename)
{
    ATM *atm = (ATM*) malloc(sizeof(ATM));
    if(atm == NULL)
    {
        perror("Could not allocate ATM");
        exit(1);
    }

    // Load init file (keys, etc.)
    FILE *fp = fopen(init_filename, "rb");
    if (fp == NULL) {
        printf("Error opening ATM initialization file\n");
        exit(64);
    }

    size_t read_count = fread(&atm->secrets, sizeof(init_data_t), 1, fp);
    fclose(fp);
    if (read_count != 1) {
        printf("Error opening ATM initialization file\n");
        exit(64);
    }

    // Set up the network state
    atm->sockfd = socket(AF_INET, SOCK_DGRAM, 0);
    if (atm->sockfd < 0) {
        perror("Could not create ATM socket");
        exit(1);
    }

    memset(&atm->rtr_addr, 0, sizeof(atm->rtr_addr));
    atm->rtr_addr.sin_family = AF_INET;
    atm->rtr_addr.sin_addr.s_addr = inet_addr("127.0.0.1");
    atm->rtr_addr.sin_port = htons(ROUTER_PORT);

    memset(&atm->atm_addr, 0, sizeof(atm->atm_addr));
    atm->atm_addr.sin_family = AF_INET;
    atm->atm_addr.sin_addr.s_addr = inet_addr("127.0.0.1");
    atm->atm_addr.sin_port = htons(ATM_PORT);

    if (bind(atm->sockfd, (struct sockaddr *)&atm->atm_addr,
             sizeof(atm->atm_addr)) < 0) {
        perror("Could not bind ATM socket");
        exit(1);
    }

    // Set up the protocol state
    atm->in_session = 0;
    atm->current_user[0] = '\0';
    atm->current_pin[0] = '\0';

    // Start sequence at 1 so bank (which initializes last_sequence to 0)
    // will accept the first message.
    atm->sequence_number = 1;

    return atm;
}

void atm_free(ATM *atm)
{
    if(atm != NULL)
    {
        if (atm->sockfd >= 0) {
            close(atm->sockfd);
        }
        free(atm);
    }
}

ssize_t atm_send(ATM *atm, char *data, size_t data_len)
{
    // Returns the number of bytes sent; negative on error
    return sendto(atm->sockfd, data, data_len, 0,
                  (struct sockaddr*) &atm->rtr_addr, sizeof(atm->rtr_addr));
}

ssize_t atm_recv(ATM *atm, char *data, size_t max_data_len)
{
    // Returns the number of bytes received; negative on error
    return recvfrom(atm->sockfd, data, max_data_len, 0, NULL, NULL);
}

// Secure send by encrypting and authenticating before sending
static ssize_t atm_send_secure(ATM *atm, const char *plaintext, size_t plaintext_len)
{
    uint8_t ciphertext[MAX_CIPHERTEXT_SIZE];

    int cipher_len = crypto_encrypt_and_auth(
        (const uint8_t*)plaintext, plaintext_len,
        ciphertext, sizeof(ciphertext),
        atm->sequence_number++,
        atm->secrets.encryption_key,
        atm->secrets.hmac_key
    );

    if (cipher_len < 0) {
        return -1;
    }

    return atm_send(atm, (char*)ciphertext, (size_t)cipher_len);
}

// Secure receive by decrypting and verifying
static ssize_t atm_recv_secure(ATM *atm, char *plaintext, size_t max_plaintext_len)
{
    uint8_t ciphertext[MAX_CIPHERTEXT_SIZE];
    uint64_t received_seq;

    ssize_t cipher_len = atm_recv(atm, (char*)ciphertext, sizeof(ciphertext));
    if (cipher_len < 0) {
        return -1;
    }

    int plain_len = crypto_decrypt_and_verify(
        ciphertext, (size_t)cipher_len,
        (uint8_t*)plaintext, max_plaintext_len,
        &received_seq,
        atm->secrets.encryption_key,
        atm->secrets.hmac_key
    );

    if (plain_len < 0) {
        return -1;  // Decryption or authentication failed
    }

    plaintext[plain_len] = '\0';
    return plain_len;
}

void atm_process_command(ATM *atm, char *command)
{
    char cmd[100];
    char arg1[256];
    char arg2[256];

    size_t len = strlen(command);
    if (len > 0 && command[len-1] == '\n') command[len-1] = '\0';

    int num_args = sscanf(command, "%99s %255s %255s", cmd, arg1, arg2);

    if (num_args < 1) {
        printf("Invalid command\n");
        return;
    }

    // begin-session <user-name>
    if (strcmp(cmd, "begin-session") == 0) {
        if (atm->in_session) {
            printf("A user is already logged in\n");
            return;
        }

        if (num_args != 2 || !is_valid_user(arg1)) {
            printf("Usage:  begin-session <user-name>\n");
            return;
        }

        // Read card file
        char filename[300];
        snprintf(filename, sizeof(filename), "%s.card", arg1);
        FILE *card_file = fopen(filename, "rb");
        if (card_file == NULL) {
            printf("Unable to access %s's card\n", arg1);
            return;
        }

        // Read IV, length, and ciphertext
        unsigned char iv[16];
        int ciphertext_len;
        unsigned char ciphertext[256];

        if (fread(iv, 1, 16, card_file) != 16 ||
            fread(&ciphertext_len, sizeof(int), 1, card_file) != 1 ||
            ciphertext_len <= 0 ||
            ciphertext_len > (int)sizeof(ciphertext) ||
            fread(ciphertext, 1, (size_t)ciphertext_len, card_file) != (size_t)ciphertext_len) {
            printf("Unable to access %s's card\n", arg1);
            fclose(card_file);
            return;
        }
        fclose(card_file);

        // Decrypt username
        EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
        if (!ctx) {
            printf("Unable to access %s's card\n", arg1);
            return;
        }

        unsigned char decrypted[256];
        int len1, len2;

        if (1 != EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), NULL,
                                    atm->secrets.encryption_key, iv) ||
            1 != EVP_DecryptUpdate(ctx, decrypted, &len1, ciphertext, ciphertext_len) ||
            1 != EVP_DecryptFinal_ex(ctx, decrypted + len1, &len2)) {
            printf("Unable to access %s's card\n", arg1);
            EVP_CIPHER_CTX_free(ctx);
            return;
        }

        EVP_CIPHER_CTX_free(ctx);
        decrypted[len1 + len2] = '\0';

        // Verify username matches
        if (strcmp((char*)decrypted, arg1) != 0) {
            printf("Unable to access %s's card\n", arg1);
            return;
        }

        // Prompt for PIN
        printf("PIN? ");
        fflush(stdout);

        char pin[10];
        if (fgets(pin, sizeof(pin), stdin) == NULL) {
            printf("Not authorized\n");
            return;
        }

        // Remove newline
        size_t pin_len = strlen(pin);
        if (pin_len > 0 && pin[pin_len-1] == '\n') {
            pin[pin_len-1] = '\0';
        }

        // Validate PIN format
        if (!is_valid_pin(pin)) {
            printf("Not authorized\n");
            return;
        }

        // Send authentication request to bank
        char request[500];
        snprintf(request, sizeof(request), "AUTH %s %s", arg1, pin);

        if (atm_send_secure(atm, request, strlen(request)) < 0) {
            printf("Not authorized\n");
            return;
        }

        // Receive response
        char response[1000];
        int n = (int)atm_recv_secure(atm, response, sizeof(response) - 1);
        if (n <= 0) {
            printf("Not authorized\n");
            return;
        }

        if (strcmp(response, "AUTH_OK") == 0) {
            atm->in_session = 1;
            strncpy(atm->current_user, arg1, 250);
            atm->current_user[250] = '\0';
            strncpy(atm->current_pin, pin, 4);
            atm->current_pin[4] = '\0';
            printf("Authorized\n");
        } else {
            printf("Not authorized\n");
        }
    }
    // withdraw <amount>
    else if (strcmp(cmd, "withdraw") == 0) {
        if (!atm->in_session) {
            printf("No user logged in\n");
            return;
        }

        if (num_args != 2 || !is_valid_amount(arg1)) {
            printf("Usage:  withdraw <amt>\n");
            return;
        }

        long amount_long = strtol(arg1, NULL, 10);
        if (amount_long <= 0 || amount_long > INT_MAX) {
            printf("Usage:  withdraw <amt>\n");
            return;
        }

        // Send withdraw request to bank
        char request[500];
        snprintf(request, sizeof(request), "WITHDRAW %s %ld",
                 atm->current_user, amount_long);

        if (atm_send_secure(atm, request, strlen(request)) < 0) {
            printf("Insufficient funds\n");
            return;
        }

        // Receive response
        char response[1000];
        int n = (int)atm_recv_secure(atm, response, sizeof(response) - 1);
        if (n <= 0) {
            printf("Insufficient funds\n");
            return;
        }

        if (strncmp(response, "WITHDRAW_OK", 11) == 0) {
            printf("$%s dispensed\n", arg1);
        } else {
            printf("Insufficient funds\n");
        }
    }
    // balance
    else if (strcmp(cmd, "balance") == 0) {
        if (!atm->in_session) {
            printf("No user logged in\n");
            return;
        }

        if (num_args != 1) {
            printf("Usage:  balance\n");
            return;
        }

        // Send balance request to bank
        char request[500];
        snprintf(request, sizeof(request), "BALANCE %s", atm->current_user);

        if (atm_send_secure(atm, request, strlen(request)) < 0) {
            printf("Unable to access account\n");
            return;
        }

        // Receive response
        char response[1000];
        int n = (int)atm_recv_secure(atm, response, sizeof(response) - 1);
        if (n <= 0) {
            printf("Unable to access account\n");
            return;
        }

        int balance;
        if (sscanf(response, "BALANCE %d", &balance) == 1) {
            printf("$%d\n", balance);
        } else {
            printf("Unable to access account\n");
        }
    }
    // end-session
    else if (strcmp(cmd, "end-session") == 0) {
        if (!atm->in_session) {
            printf("No user logged in\n");
            return;
        }

        if (num_args != 1) {
            printf("Usage:  end-session\n");
            return;
        }

        atm->in_session = 0;
        atm->current_user[0] = '\0';
        atm->current_pin[0] = '\0';
        printf("User logged out\n");
    }
    else {
        printf("Invalid command\n");
    }
}
