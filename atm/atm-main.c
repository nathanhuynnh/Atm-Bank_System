/* 
 * The main program for the ATM.
 *
 * You are free to change this as necessary.
 */

#include "atm.h"
#include <stdio.h>
#include <stdlib.h>

int main(int argc, char **argv)
{
    char user_input[1000];

    if (argc != 2) {
        printf("Usage:  atm <init-file>\n");
        return 64;
    }

    ATM *atm = atm_create(argv[1]);

    atm_print_prompt(atm);

    while (fgets(user_input, sizeof(user_input), stdin) != NULL)
    {
        atm_process_command(atm, user_input);
        atm_print_prompt(atm);
    }

    atm_free(atm);
    return EXIT_SUCCESS;
}


// static const char prompt[] = "ATM: ";

// int main()
// {
//     char user_input[1000];

//     ATM *atm = atm_create();

//     printf("%s", prompt);
//     fflush(stdout);

//     while (fgets(user_input, 10000,stdin) != NULL)
//     {
//         atm_process_command(atm, user_input);
//         printf("%s", prompt);
//         fflush(stdout);
//     }
// 	return EXIT_SUCCESS;
// }
