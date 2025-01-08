#include <Windows.h>
#include <stdio.h>

#include "entropyreducer.h"

// File extension of generated Payload
#define PREFIX ".cl"

// Error printing function
BOOL ReportError(const char* WinApiName) {
	printf("[!] \"%s\" [ FAILED ] \t%d \n", WinApiName, GetLastError());
	return FALSE;
}

// Function To Read the Payload File
BOOL ReadPayloadFile(IN PCSTR cFileInput, OUT PBYTE* pPayloadData, OUT PSIZE_T sPayloadSize) {
	
	// Local Variable definitions
	HANDLE	hFile = INVALID_HANDLE_VALUE;
	DWORD	dwFileSize = NULL;
	DWORD	dwNumberOfBytesRead = NULL;
	PBYTE	pBuffer = NULL;

	// Open the file
	hFile = CreateFileA(cFileInput, GENERIC_READ, 0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
	if (hFile == INVALID_HANDLE_VALUE) {
		return ReportError("CreateFileA");
	}

	// Get the size of the file
	if ((dwFileSize = GetFileSize(hFile, NULL)) == INVALID_FILE_SIZE) {
		return ReportError("GetFileSize");
	}

	// Allocate memory for the file
	pBuffer = (PBYTE)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, dwFileSize);
	if (!pBuffer)
		return ReportError("HeapAlloc");

	// Read the file
	if (!ReadFile(hFile, pBuffer, dwFileSize, &dwNumberOfBytesRead, NULL)) {
		printf("[i] Read %ld from %ld Bytes \n", dwNumberOfBytesRead, dwFileSize);
		return ReportError("ReadFile");
	}

	// Set the Payload Data and Size
	*pPayloadData = pBuffer;
	*sPayloadSize = dwNumberOfBytesRead;

	// Close the file
	CloseHandle(hFile);

	// Return Failure if the Payload Data or size is NULL
	if (*pPayloadData == NULL || *sPayloadSize == NULL) {
		return FALSE;
	}

	return TRUE;
}


// Function to Write the Payload File
