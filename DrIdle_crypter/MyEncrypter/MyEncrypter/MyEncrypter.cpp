#include "stdafx.h"
#include <stdlib.h>
#include <stdio.h>
#include "aes256.h"

int main (int argc, char *argv[])
{
	if (argv[1] == NULL) return 0;

	//*********** open file to encrypt ************
	FILE *inFile = fopen(argv[1], "rb");
	fseek(inFile , 0 , SEEK_END);
	unsigned long lSize = ftell(inFile);
	rewind(inFile);
	unsigned char *text = (unsigned char*) malloc (sizeof(unsigned char)*lSize);
	fread(text,1,lSize,inFile);
	fclose (inFile);
	//*********************************************

	puts("Encrypting...");

	//************ AES encryption ********************
	unsigned char aesKey[32] = {
		0x53, 0x28, 0x40, 0x6e, 0x2f, 0x64, 0x63, 0x5d, 0x2d, 0x61, 0x77, 0x40, 0x76, 0x71, 0x77, 0x28, 
		0x74, 0x61, 0x7d, 0x66, 0x61, 0x73, 0x3b, 0x5d, 0x66, 0x6d, 0x3c, 0x3f, 0x7b, 0x66, 0x72, 0x36
	};

	unsigned char *buf;

	aes256_context ctx;
	aes256_init(&ctx, aesKey);

	for (unsigned long i = 0; i < lSize/16; i++) {
		buf = text + (i * 16);
		aes256_encrypt_ecb(&ctx, buf);
	}
	
	aes256_done(&ctx);
	//************************************************

	//************* write encrypted data to file ***********
	if (text != NULL) {
		char absPath[500];
		if (strrchr(argv[0], '\\') == NULL) {
			strcpy (absPath, "encrypted.dat");
		} else {
			char* path = argv[0];
			path[strrchr(argv[0], '\\') - path + 1] = 0;
			strcpy (absPath, path);
			strcat (absPath,"encrypted.dat");
		}
		FILE *outFile = fopen(absPath, "wb");
		fwrite(text, lSize, 1, outFile);
		fclose (outFile);
	}
	free(text);
	//******************************************************

	puts("done");

    return 0;
} /* main */
