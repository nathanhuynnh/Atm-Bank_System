#include "init.h"
#include "../protocol.h"
#include <openssl/rand.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

int init_create_files(const char *filename)
{
    char bank_file[1024];
    char atm_file[1024];
    FILE *bank_fp = NULL;
    FILE *atm_fp = NULL;

    // Construct file paths
    snprintf(bank_file, sizeof(bank_file), "%s.bank", filename);
    snprintf(atm_file, sizeof(atm_file), "%s.atm", filename);

    // Check if files already exist
    if (access(bank_file, F_OK) == 0 || access(atm_file, F_OK) == 0)
    {
        printf("Error: one of the files already exists\n");
        return 63;
    }

    // Try to create the bank file
    bank_fp = fopen(bank_file, "w");
    if (bank_fp == NULL)
    {
        printf("Error creating initialization files\n");
        return 64;
    }

    // Try to create the ATM file
    atm_fp = fopen(atm_file, "w");
    if (atm_fp == NULL)
    {
        fclose(bank_fp);
        unlink(bank_file);  // Remove the bank file if ATM file creation fails
        printf("Error creating initialization files\n");
        return 64;
    }

    // Generate cryptographic keys and initialization data
    init_data_t init_data;
    
    // Generate random encryption key (AES-256)
    if (RAND_bytes(init_data.encryption_key, AES_KEY_SIZE) != 1)
    {
        fclose(bank_fp);
        fclose(atm_fp);
        unlink(bank_file);
        unlink(atm_file);
        printf("Error creating initialization files\n");
        return 64;
    }
    
    // Generate random HMAC key (for message authentication)
    if (RAND_bytes(init_data.hmac_key, HMAC_KEY_SIZE) != 1)
    {
        fclose(bank_fp);
        fclose(atm_fp);
        unlink(bank_file);
        unlink(atm_file);
        printf("Error creating initialization files\n");
        return 64;
    }
    
    // Generate initial nonce (for sequence numbers/replay protection)
    if (RAND_bytes(init_data.initial_nonce, NONCE_SIZE) != 1)
    {
        fclose(bank_fp);
        fclose(atm_fp);
        unlink(bank_file);
        unlink(atm_file);
        printf("Error creating initialization files\n");
        return 64;
    }
    
    // Write the same initialization data to both files
    // Both bank and ATM need the same keys to communicate securely
    size_t written = fwrite(&init_data, sizeof(init_data_t), 1, bank_fp);
    if (written != 1)
    {
        fclose(bank_fp);
        fclose(atm_fp);
        unlink(bank_file);
        unlink(atm_file);
        printf("Error creating initialization files\n");
        return 64;
    }
    
    written = fwrite(&init_data, sizeof(init_data_t), 1, atm_fp);
    if (written != 1)
    {
        fclose(bank_fp);
        fclose(atm_fp);
        unlink(bank_file);
        unlink(atm_file);
        printf("Error creating initialization files\n");
        return 64;
    }
    
    // Close files
    if (fclose(bank_fp) != 0 || fclose(atm_fp) != 0)
    {
        // If closing fails, try to clean up
        unlink(bank_file);
        unlink(atm_file);
        printf("Error creating initialization files\n");
        return 64;
    }

    printf("Successfully initialized bank state\n");
    return 0;
}

