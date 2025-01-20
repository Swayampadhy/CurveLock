#pragma once

#include <Windows.h>

//Function protortypes
int fetchPayload();
FARPROC GetProcAddressQ(IN HMODULE hModule, IN LPCSTR lpApiName);