#pragma once

#include <Windows.h>

extern BYTE bKey[30];
extern DWORD dwFileSize;
extern DWORD dwPaddedFileSize;

extern DWORD dwSplitMulti;
extern DWORD dwSplitIncrease;

extern DWORD dwEncryptEndMarker;
extern DWORD dwEncryptStartMarker;

void stub_start();

void SIMPLE_ENCRYPT( BYTE* pBuffer, DWORD dwLen, BYTE* bKey, DWORD dwKeyLen, bool bSkip );
DWORD Align( DWORD dwVal, DWORD dwAlignment );