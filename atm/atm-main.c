/* 
 * The main program for the ATM.
 *
 * You are free to change this as necessary.
 */

#include "atm.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int main(int argc, char **argv)
{
    if (argc != 2)
    {
        printf("Usage:  atm <init-file>\n");
        return 64;
    }

    char user_input[1000];

    ATM *atm = atm_create(argv[1]);

    while (1)
    {
        // Display appropriate prompt based on session state
        if (atm->in_session) {
            printf("ATM (%s):  ", atm->current_user);
        } else {
            printf("ATM: ");
        }
        fflush(stdout);

        if (fgets(user_input, sizeof(user_input), stdin) == NULL) {
            break;
        }

        atm_process_command(atm, user_input);
    }

    atm_free(atm);
    return EXIT_SUCCESS;
}
