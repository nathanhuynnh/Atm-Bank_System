#include "atm.h"
#include "ports.h"
#include <string.h>
#include <stdlib.h>
#include <unistd.h>

#include <stdio.h>
#include <ctype.h>

// Helpers
static int is_valid_user(const char *name) {
    if (name == NULL) return 0;
    size_t len = strlen(name);
    if (len == 0 || len > 250) return 0;
    for (size_t i = 0; i < len; i++) {
        if (!isalpha((unsigned char)name[i])) return 0;
    }
    return 1;
}

static int is_valid_amount(const char *amt) {
    if (amt == NULL || amt[0] == '\0') return 0;
    for (int i = 0; amt[i]; i++) {
        if (!isdigit((unsigned char)amt[i])) return 0;
    }
    return 1;
}

/* simple text protocol to bank; your team can later replace with encrypted messages */

static int atm_check_user_exists(ATM *atm, const char *user) {
    char sendbuf[512];
    char recvbuf[512];
    int n;

    snprintf(sendbuf, sizeof(sendbuf), "CHECK-USER %s\n", user);
    atm_send(atm, sendbuf, strlen(sendbuf));

    n = atm_recv(atm, recvbuf, sizeof(recvbuf) - 1);
    if (n <= 0) return 0;

    recvbuf[n] = '\0';
    if (strncmp(recvbuf, "OK", 2) == 0) return 1;
    return 0;
}

static int atm_auth_user(ATM *atm, const char *user, const char *pin) {
    char sendbuf[512];
    char recvbuf[512];
    int n;

    snprintf(sendbuf, sizeof(sendbuf), "AUTH %s %s\n", user, pin);
    atm_send(atm, sendbuf, strlen(sendbuf));

    n = atm_recv(atm, recvbuf, sizeof(recvbuf) - 1);
    if (n <= 0) return 0;

    recvbuf[n] = '\0';
    if (strncmp(recvbuf, "OK", 2) == 0) return 1;
    return 0;
}

static int atm_withdraw_remote(ATM *atm, const char *user, const char *amt_str) {
    char sendbuf[512];
    char recvbuf[512];
    int n;

    snprintf(sendbuf, sizeof(sendbuf), "WITHDRAW %s %s\n", user, amt_str);
    atm_send(atm, sendbuf, strlen(sendbuf));

    n = atm_recv(atm, recvbuf, sizeof(recvbuf) - 1);
    if (n <= 0) return -1;

    recvbuf[n] = '\0';
    if (strncmp(recvbuf, "OK", 2) == 0) return 1;
    if (strncmp(recvbuf, "NOFUNDS", 7) == 0) return 0;
    return -1;
}

static int atm_balance_remote(ATM *atm, const char *user, int *balance_out) {
    char sendbuf[512];
    char recvbuf[512];
    int n;

    snprintf(sendbuf, sizeof(sendbuf), "BALANCE %s\n", user);
    atm_send(atm, sendbuf, strlen(sendbuf));

    n = atm_recv(atm, recvbuf, sizeof(recvbuf) - 1);
    if (n <= 0) return 0;

    recvbuf[n] = '\0';

    char cmd[64];
    int bal;
    if (sscanf(recvbuf, "%63s %d", cmd, &bal) != 2) return 0;
    if (strcmp(cmd, "BALANCE") != 0) return 0;

    *balance_out = bal;
    return 1;
}

// Start of original code
ATM* atm_create(char *init_fname)
{
    ATM *atm = (ATM*) malloc(sizeof(ATM));
    if(atm == NULL)
    {
        perror("Could not allocate ATM");
        exit(1);
    }

    // Set up the network state
    atm->sockfd=socket(AF_INET,SOCK_DGRAM,0);

    bzero(&atm->rtr_addr,sizeof(atm->rtr_addr));
    atm->rtr_addr.sin_family = AF_INET;
    atm->rtr_addr.sin_addr.s_addr=inet_addr("127.0.0.1");
    atm->rtr_addr.sin_port=htons(ROUTER_PORT);

    bzero(&atm->atm_addr, sizeof(atm->atm_addr));
    atm->atm_addr.sin_family = AF_INET;
    atm->atm_addr.sin_addr.s_addr=inet_addr("127.0.0.1");
    atm->atm_addr.sin_port = htons(ATM_PORT);
    bind(atm->sockfd,(struct sockaddr *)&atm->atm_addr,sizeof(atm->atm_addr));

    // Set up the protocol state
    // TODO set up more, as needed
    atm->logged_in = 0;
    atm->current_user[0] = '\0';

    /* read <init-fname>.atm into atm->secrets */
    FILE *fp = fopen(init_fname, "rb");
    if (fp == NULL) {
        printf("Error opening ATM initialization file\n");
        exit(64);
    }
    size_t read_count = fread(&atm->secrets, sizeof(init_data_t), 1, fp);
    if (read_count != 1) {
        printf("Error opening ATM initialization file\n");
        fclose(fp);
        exit(64);
    }
    fclose(fp);

    return atm;
}

void atm_free(ATM *atm)
{
    if(atm != NULL)
    {
        close(atm->sockfd);
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

void atm_process_command(ATM *atm, char *command)
{
    // TODO: Implement the ATM's side of the ATM-bank protocol

	/*
	 * The following is a toy example that simply sends the
	 * user's command to the bank, receives a message from the
	 * bank, and then prints it to stdout.
	 */

	/*
    char recvline[10000];
    int n;

    atm_send(atm, command, strlen(command));
    n = atm_recv(atm,recvline,10000);
    recvline[n]=0;
    fputs(recvline,stdout);
	*/
    char cmd[64];
    char arg1[256];
    char arg2[256];

    size_t len = strlen(command);
    if (len > 0 && command[len-1] == '\n') {
        command[len-1] = '\0';
    }

    int num_args = sscanf(command, "%63s %255s %255s", cmd, arg1, arg2);
    if (num_args <= 0) {
        return; // empty line
    }

    // begin-session <user-name>
    if (strcmp(cmd, "begin-session") == 0) {
        if (atm->logged_in) {
            printf("A user is already logged in\n");
            return;
        }

        if (num_args != 2 || !is_valid_user(arg1)) {
            printf("Usage: begin-session <user-name>\n");
            return;
        }

        const char *user = arg1;

        // Ask bank if user exists
        if (!atm_check_user_exists(atm, user)) {
            printf("No such user\n");
            return;
        }

        // Check card file
        char card_filename[300];
        snprintf(card_filename, sizeof(card_filename), "%s.card", user);
        FILE *card_fp = fopen(card_filename, "rb");
        if (card_fp == NULL) {
            printf("Unable to access %s's card\n", user);
            return;
        }
        fclose(card_fp);

        // Prompt for PIN
        char pin_buf[100];
        printf("PIN? ");
        fflush(stdout);

        if (fgets(pin_buf, sizeof(pin_buf), stdin) == NULL) {
            printf("Not authorized\n");
            return;
        }

        size_t pin_len = strlen(pin_buf);
        if (pin_len > 0 && pin_buf[pin_len-1] == '\n') {
            pin_buf[pin_len-1] = '\0';
            pin_len--;
        }

        if (pin_len != 4) {
            printf("Not authorized\n");
            return;
        }
        for (int i = 0; i < 4; i++) {
            if (!isdigit((unsigned char)pin_buf[i])) {
                printf("Not authorized\n");
                return;
            }
        }

        // Authenticate with bank
        if (!atm_auth_user(atm, user, pin_buf)) {
            printf("Not authorized\n");
            return;
        }

        atm->logged_in = 1;
        strncpy(atm->current_user, user, 250);
        atm->current_user[250] = '\0';
        printf("Authorized\n");

    // withdraw <amt>
    } else if (strcmp(cmd, "withdraw") == 0) {
        if (!atm->logged_in) {
            printf("No user logged in\n");
            return;
        }

        if (num_args != 2 || !is_valid_amount(arg1)) {
            printf("Usage: withdraw <amt>\n");
            return;
        }

        int res = atm_withdraw_remote(atm, atm->current_user, arg1);
        if (res == 0) {
            printf("Insufficient funds\n");
        } else if (res == 1) {
            printf("$%s dispensed\n", arg1);
        } else {
            printf("Insufficient funds\n"); // conservative failure behavior
        }

    // balance
    } else if (strcmp(cmd, "balance") == 0) {
        if (!atm->logged_in) {
            printf("No user logged in\n");
            return;
        }

        if (num_args != 1) {
            printf("Usage: balance\n");
            return;
        }

        int bal;
        if (atm_balance_remote(atm, atm->current_user, &bal)) {
            printf("$%d\n", bal);
        } else {
            printf("$0\n");  // protocol error fallback
        }

    // end-session
    } else if (strcmp(cmd, "end-session") == 0) {
        if (!atm->logged_in) {
            printf("No user logged in\n");
            return;
        }
        atm->logged_in = 0;
        atm->current_user[0] = '\0';
        printf("User logged out\n");

    // anything else
    } else {
        printf("Invalid command\n");
    }
}
