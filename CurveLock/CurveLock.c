#include <Windows.h>
#include <stdio.h>
#include "common.h"

// Function to report WinApi Errors
BOOL ReportError(const char* WinApiName) {
    printf("[!] \"%s\" [ FAILED ] \t%d \n", WinApiName, GetLastError());
    return FALSE;
}

int main() {

}