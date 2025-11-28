/* 
 * The main program for init.
 *
 * You are free to change this as necessary.
 */

#include "init.h"
#include <stdio.h>
#include <stdlib.h>

int main(int argc, char **argv)
{
    if (argc != 2)
    {
        printf("Usage:  init <filename>\n");
        return 62;
    }

    return init_create_files(argv[1]);
}

