/*
 * File name: test_random.cpp
 * Date:      2010-08-23 18:44
 * Author:    Kristjan Runarsson
 */

#include <iostream>
#include <string>
#include <stdlib.h>
#include "aes_crypt.h"
#include "aes_utils.h"

using namespace std;

int cFlag = 0;

void printKey(unsigned char* pBytes, unsigned long dLength, int textWidth=8)
{
    int bytecount=0;

	if(cFlag){
		printf("{ ");
	} else {
		textWidth = 16;
		printf("  ");
	}

    for(unsigned long i=0;i<dLength;i++)
    {

		if(cFlag){
			printf("0x");

        	printf("%.2x",pBytes[i]);

			if(i == dLength-1){
				printf(" }");
			} else {
				printf(", ");
			}
		} else {
        	printf("%.2x ",pBytes[i]);
		}

        if ( ++bytecount == textWidth )
        {
            printf("\n  ");
            bytecount=0;
        }

    }

    if ( bytecount != 0 ) {
        printf("\n");
	}
}


void usage(){
	fprintf(stderr, "SYNOPSIS\n");
	fprintf(stderr, "    generatekey -l <length> [-c]\n\n");

	fprintf(stderr, "DESCRIPTION\n");
	fprintf(stderr, "    A small convenience utility to generates an "
			"arbatrarily long random key. \n    Running it with no options"
			" will generate a key of 16 hex values.\n\n");

	fprintf(stderr, "OPTIONS\n");
	fprintf(stderr, "    -l    Key length in bytes.\n");
	fprintf(stderr, "    -c    Prints key in copy/paste friendly form.\n\n");

}

int main(int argc, char **argv) {

	int index;
	int c;

	int keyLength = 16;

	char* conf;
	while ((c = getopt (argc, argv, "l:ch")) != -1)
	switch (c) {
		case 'l':
			keyLength = atoi(optarg);
			if(keyLength == 0){
				fprintf(stderr, "Error - Non numeric key lenght.");
				exit(1);
			}
			break;
		case 'c':
			cFlag = 1;
			break;
		case 'h':
			usage();
			exit(0);
		case '?':
			usage();
			exit(0);
	}

	for (index = optind; index < argc; index++){
		printf("Trailing argument(s): %s\n", argv[index]);
	}

	byte_ard newKey[keyLength];

	if(!generateKeyOfLength(newKey, keyLength)){
		printf("Unable to generate key.\n");
		return 1;
	}

	printKey(newKey, keyLength);

    return 0;
} // end main()
