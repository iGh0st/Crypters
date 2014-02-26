#define _WIN32_WINNT _WIN32_WINNT_WINXP

#include <Windows.h>
#include <tchar.h>
#include <stdio.h>

#include "build.h"
#include "stub.h"

int _tmain( int argc, wchar_t* argv[] )
{
	if ( argc < 2 )
	{
		wprintf( L"\n************************************************\n" );
		wprintf( L"ERROR: Not enough parameters!\n" );
		wprintf( L"Format: %s file_to_crypt.exe\n", argv[0] );
		wprintf( L"************************************************\n" );
		return 0;
	}

	DWORD dwFileAttributes = GetFileAttributes( argv[1] );

	if ( dwFileAttributes == INVALID_FILE_ATTRIBUTES )
	{
		int iError = GetLastError();
		wprintf( L"\n************************************************\n" );
		wprintf( L"ERROR: GetLastError(): 0x%X!\n", iError );
		wprintf( L"Format: %s file_to_crypt.exe\n", argv[0] );
		wprintf( L"************************************************\n" );
		return 0;
	}

	srand( GetTickCount() );

	if ( CryptFile( argv[1] ) )
	{
		wprintf( L"\n\n************************************************\n" );
		wprintf( L"File successfully crypted!\n" );
		wprintf( L"************************************************\n" );
	}
	else
	{
		wprintf( L"\n\n************************************************\n" );
		wprintf( L"Failed to crypt file!\n" );
		wprintf( L"************************************************\n" );
	}

	system( "pause" );

	return 0;
}