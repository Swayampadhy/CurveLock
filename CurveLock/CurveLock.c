#include <Windows.h>
#include <stdio.h>
#include "EntropyReducer.h"

// Function to report WinApi Errors
BOOL ReportError(const char* ApiName) {
	printf("[!] \"%s\" [ FAILED ] \t%d \n", ApiName, GetLastError());
	return FALSE;
}

