#include "bank.h"
#include "ports.h"
#include "../protocol.h"
#include "../util/crypto.h"
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <stdio.h>
#include <limits.h>
#include <ctype.h>
#include <openssl/evp.h>
#include <openssl/rand.h>

//Helper functions
int is_valid_user(const char *name) {
    if (name == NULL || strlen(name) == 0 || strlen(name) > 250) return 0;
    for (int i = 0; name[i]; i++) {
        if (!isalpha(name[i])) return 0;
    }
    return 1;
}

int is_valid_pin(const char *pin) {
    if (pin == NULL || strlen(pin) != 4) return 0;
    for (int i = 0; i < 4; i++) {
        if (!isdigit(pin[i])) return 0;
    }
    return 1;
}

int is_valid_amount(const char *amt) {
    if (amt == NULL || strlen(amt) == 0) return 0;
    for (int i = 0; amt[i]; i++) {
        if (!isdigit(amt[i])) return 0;
    }
    return 1;
}

void add_user_to_list(Bank *bank, const char *name, const char *pin, int balance) {
    User *new_user = (User*)malloc(sizeof(User));
    strncpy(new_user->username, name, 250);
    new_user->username[250] = '\0';
    strncpy(new_user->pin, pin, 4);
    new_user->balance = balance;
    new_user->next = bank->users;
    bank->users = new_user;
}

User* find_user(Bank *bank, const char *name) {
    User *cur = bank->users;
    while (cur != NULL) {
        if (strcmp(cur->username, name) == 0) return cur;
        cur = cur->next;
    }
    return NULL;
}

Bank* bank_create(char *init_fname)
{
    Bank *bank = (Bank*) malloc(sizeof(Bank));
    if(bank == NULL)
    {
        perror("Could not allocate Bank");
        exit(1);
    }

    bank->users = NULL;
    
    //Load Init file
    FILE *fp = fopen(init_fname, "rb");
    if (fp == NULL) {
        printf("Error opening bank initialization file\n");
        exit(64);
    }

    //Read keys into bank struct
    size_t read_count = fread(&bank->secrets, sizeof(init_data_t), 1, fp);
    if (read_count != 1) {
        printf("Error opening bank initialization file\n");
        fclose(fp);
        exit(64);
    }
    fclose(fp);

    // Set up the network state
    bank->sockfd=socket(AF_INET,SOCK_DGRAM,0);
    bzero(&bank->rtr_addr,sizeof(bank->rtr_addr));
    bank->rtr_addr.sin_family = AF_INET;
    bank->rtr_addr.sin_addr.s_addr=inet_addr("127.0.0.1");
    bank->rtr_addr.sin_port=htons(ROUTER_PORT);

    bzero(&bank->bank_addr, sizeof(bank->bank_addr));
    bank->bank_addr.sin_family = AF_INET;
    bank->bank_addr.sin_addr.s_addr=inet_addr("127.0.0.1");
    bank->bank_addr.sin_port = htons(BANK_PORT);
    bind(bank->sockfd,(struct sockaddr *)&bank->bank_addr,sizeof(bank->bank_addr));

    // Set up the protocol state
    bank->last_sequence = 0;

    return bank;
}

void bank_free(Bank *bank)
{
    if(bank != NULL)
    {
        User *cur = bank->users;
        while (cur != NULL) {
            User *temp = cur;
            cur = cur->next;
            free(temp);
        }
        close(bank->sockfd);
        free(bank);
    }
}

ssize_t bank_send(Bank *bank, char *data, size_t data_len)
{
    // Returns the number of bytes sent; negative on error
    return sendto(bank->sockfd, data, data_len, 0,
                  (struct sockaddr*) &bank->rtr_addr, sizeof(bank->rtr_addr));
}

ssize_t bank_recv(Bank *bank, char *data, size_t max_data_len)
{
    // Returns the number of bytes received; negative on error
    return recvfrom(bank->sockfd, data, max_data_len, 0, NULL, NULL);
}

// Secure send by encrypting and authenticating
static ssize_t bank_send_secure(Bank *bank, const char *plaintext, size_t plaintext_len, uint64_t sequence)
{
    uint8_t ciphertext[MAX_CIPHERTEXT_SIZE];
    
    int cipher_len = crypto_encrypt_and_auth(
        (const uint8_t*)plaintext, plaintext_len,
        ciphertext, sizeof(ciphertext),
        sequence,
        bank->secrets.encryption_key,
        bank->secrets.hmac_key
    );
    
    if (cipher_len < 0) {
        return -1;
    }
    
    return bank_send(bank, (char*)ciphertext, cipher_len);
}

// Secure receive by decrypting and verifying
static ssize_t bank_recv_secure(Bank *bank, char *plaintext, size_t max_plaintext_len, uint64_t *received_seq)
{
    uint8_t ciphertext[MAX_CIPHERTEXT_SIZE];
    
    ssize_t cipher_len = bank_recv(bank, (char*)ciphertext, sizeof(ciphertext));
    if (cipher_len < 0) {
        return -1;
    }
    
    int plain_len = crypto_decrypt_and_verify(
        ciphertext, cipher_len,
        (uint8_t*)plaintext, max_plaintext_len,
        received_seq,
        bank->secrets.encryption_key,
        bank->secrets.hmac_key
    );
    
    if (plain_len < 0) {
        return -1;  // Decryption or authentication failed
    }
    
    plaintext[plain_len] = '\0';
    return plain_len;
}

void bank_process_local_command(Bank *bank, char *command, size_t len)
{
    // TODO: Implement the bank's local commands
    char cmd[100]; // Action (deposit)
    char arg1[256]; // Argument 1 (username)
    char arg2[256]; // Argument 2 (pin or amount)
    char arg3[256]; // Argument 3 (balance)


    if  (len > 0 && command[len-1] == '\n') command[len-1] = '\0';
    int num_args = sscanf(command, "%s %s %s %s", cmd, arg1, arg2, arg3);

    //Create user <name> <pin> <balance>
    if (strcmp(cmd, "create-user") == 0) {
        if (num_args != 4 || !is_valid_user(arg1) || !is_valid_pin(arg2) || !is_valid_amount(arg3)) {
            printf("Usage:  create-user <user-name> <pin> <balance>\n");
            return;
        }

        char *endptr;
        long bal = strtol(arg3, &endptr, 10);
        
        if (bal > INT_MAX || bal < 0) {
            printf("Usage:  create-user <user-name> <pin> <balance>\n");
            return;
        }

        if (find_user(bank, arg1) != NULL) {
            printf("Error:  user %s already exists\n", arg1);
            return;
        }

        //Create encrypted card file
        char filename[300];
        snprintf(filename, sizeof(filename), "%s.card", arg1);
        FILE *card_file = fopen(filename, "wb");
        if (card_file == NULL) {
            printf("Error creating card file for user %s\n", arg1);
            return;
        }

        //Write encrypted token
        unsigned char iv[16];
        unsigned char ciphertext[256]; //Buffer for encrypted data
        int len_p1, len_p2;
        int plaintext_len = strlen(arg1) + 1;

        //Create random initialization vector (IV)
        if (!RAND_bytes(iv, sizeof(iv))) {
            printf("Error creating random initialization vector\n");
            fclose(card_file);
            return;
        }

        //Initialize OpenSSL Cipher
        EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
        if (!ctx) {
            printf("Error creating cipher context\n");
            fclose(card_file);
            return;
        }

        //Setup AES-256-CBC encryption using the bank's secret key
        if (1 != EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, bank->secrets.encryption_key, iv)) {
            printf("Error initializing encryption\n");
            EVP_CIPHER_CTX_free(ctx);
            fclose(card_file);
            return;
        }

        //Encrypt the username (arg1)
        if (1 != EVP_EncryptUpdate(ctx, ciphertext, &len_p1, (unsigned char*)arg1, plaintext_len)) {
            printf("Error encrypting username\n");
            EVP_CIPHER_CTX_free(ctx);
            fclose(card_file);
            return;
        }

        //Handling padding
        if (1 != EVP_EncryptFinal_ex(ctx, ciphertext + len_p1, &len_p2)) {
            printf("Error finalizing encryption\n");
            EVP_CIPHER_CTX_free(ctx);
            fclose(card_file);
            return;
        }
        
        int total_cipher_len = len_p1 + len_p2;
        EVP_CIPHER_CTX_free(ctx);

        fwrite(iv, 1, 16, card_file);
        fwrite(&total_cipher_len, sizeof(int), 1, card_file);
        fwrite(ciphertext, 1, total_cipher_len, card_file);
        
        fclose(card_file);

        add_user_to_list(bank, arg1, arg2, (int)bal);
        printf("Created user %s\n", arg1);


        //Deposit <name> <amount>
    } else if (strcmp(cmd, "deposit") == 0 ) {
        if (num_args != 3 || !is_valid_user(arg1) || !is_valid_amount(arg2)) {
            printf("Usage:  deposit <user-name> <amt>\n");
            return;
        }

        User *u = find_user(bank, arg1);

        if (u == NULL) {
            printf("No such user\n");
            return;
        }

        long amt = strtol(arg2, NULL, 10);

        //Overflow check: max - balance < amount
        if ((long)INT_MAX - u->balance < amt) {
            printf("Too rich for this program\n");
            return;
        }

        u->balance += (int)amt;
        printf("$%ld added to %s's account\n", amt, arg1);


        //Balance <name>
    } else if (strcmp(cmd, "balance") == 0) {
        if (num_args != 2 || !is_valid_user(arg1)) {
            printf("Usage:  balance <user-name>\n");
            return;
        }

        User *u = find_user(bank, arg1);

        if (u == NULL) {
            printf("No such user\n");
            return;
        }
        printf("$%d\n", u->balance);

    } else {
        printf("Invalid command\n");
    }
}

void bank_process_remote_command(Bank *bank, char *command, size_t len)
{
    // TODO: Implement the bank side of the ATM-bank protocol
    char plaintext[1000];
    uint64_t received_seq;
    
    // Decrypt and verify the incoming message
    int plain_len = crypto_decrypt_and_verify(
        (const uint8_t*)command, len,
        (uint8_t*)plaintext, sizeof(plaintext) - 1,
        &received_seq,
        bank->secrets.encryption_key,
        bank->secrets.hmac_key
    );
    
    if (plain_len < 0) {
        return;  // Invalid message, ignore
    }
    
    plaintext[plain_len] = '\0';
    
    // Check for replay attack, if detected ignore it
    if (received_seq <= bank->last_sequence) {
        return;
    }
    bank->last_sequence = received_seq;
    
    char cmd[100];
    char arg1[256];
    char arg2[256];
    
    int num_args = sscanf(plaintext, "%s %s %s", cmd, arg1, arg2);
    
    if (num_args < 1) {
        return;
    }
    
    // AUTH <username> <pin>
    if (strcmp(cmd, "AUTH") == 0 && num_args == 3) {
        User *u = find_user(bank, arg1);
        if (u != NULL && strcmp(u->pin, arg2) == 0) {
            bank_send_secure(bank, "AUTH_OK", 7, received_seq + 1);
        } else {
            bank_send_secure(bank, "AUTH_FAIL", 9, received_seq + 1);
        }
    }
    // WITHDRAW <username> <amount>
    else if (strcmp(cmd, "WITHDRAW") == 0 && num_args == 3) {
        User *u = find_user(bank, arg1);
        if (u == NULL) {
            bank_send_secure(bank, "WITHDRAW_FAIL", 13, received_seq + 1);
            return;
        }
        
        int amount = atoi(arg2);
        if (amount <= 0 || amount > u->balance) {
            bank_send_secure(bank, "WITHDRAW_FAIL", 13, received_seq + 1);
            return;
        }
        
        u->balance -= amount;
        bank_send_secure(bank, "WITHDRAW_OK", 11, received_seq + 1);
    }
    // BALANCE <username>
    else if (strcmp(cmd, "BALANCE") == 0 && num_args == 2) {
        User *u = find_user(bank, arg1);
        if (u == NULL) {
            bank_send_secure(bank, "BALANCE_FAIL", 12, received_seq + 1);
            return;
        }
        
        char response[100];
        snprintf(response, sizeof(response), "BALANCE %d", u->balance);
        bank_send_secure(bank, response, strlen(response), received_seq + 1);
    }
}
