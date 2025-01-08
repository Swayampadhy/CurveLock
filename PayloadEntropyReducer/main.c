#include <Windows.h>
#include <stdio.h>

#include "entropyreducer.h"

// Serialization and Obfuscation Function
BOOL Obfuscate(IN PBYTE PayloadBuffer, IN SIZE_T PayloadSize, OUT PBYTE* ObfuscatedBuffer, OUT PSIZE_T ObfuscatedSize) {
    // Initialize the linked list
    PLINKED_LIST pLinkedList = NULL;
    *ObfuscatedSize = PayloadSize;

    // convert the payload to a linked list
    if (!InitializePayloadList(PayloadBuffer, ObfuscatedSize, &pLinkedList)) {
        printf("[!] InitializePayloadList failed\n");
        return 0;
    }

    // ObfuscatedSize now is the size of the serialized linked list
    // pLinkedList is the head of the linked list

    // randomize the linked list (sorted by the value of 'Buffer[0] ^ Buffer[1] ^ Buffer[3]')
    MergeSort(&pLinkedList, SORT_BY_BUFFER);

    PLINKED_LIST pTmpHead = pLinkedList;
    SIZE_T BufferSize = 0;
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

    // If buffer or size is NULL, return Failure
    if (*ObfuscatedBuffer != NULL && *ObfuscatedSize > PayloadSize) {
        printf("[+] Obfuscation completed successfully\n");
        return 1;
    }
    else {
        printf("[!] Obfuscation failed\n");
        return 0;
    }
}

int main(int argc, char* argv[]) {

	// Command Line Arguments
	if (!(argc >= 2)) {
		printf("[!] Please Specify A Input File To Obfuscate ... \n");
		return -1;
	}
	printf("[i] BUFF_SIZE : [ 0x%0.4X ] - NULL_BYTES : [ 0x%0.4X ]\n", BUFF_SIZE, NULL_BYTES);

	// Initialize Variables
	SIZE_T	RawPayloadSize = NULL;
	PBYTE	RawPayloadBuffer = NULL;

	// Read The Payload
	printf("[i] Reading \"%s\" ... ", argv[1]);
	if (!ReadPayloadFile(argv[1], &RawPayloadBuffer, &RawPayloadSize)) {
		return -1;
	}
	printf("[+] DONE \n");
	printf("\t>>> Raw Payload Size : %ld \n\t>>> Read Payload Located At : 0x%p \n", RawPayloadSize, RawPayloadBuffer);

	// Obfuscate The Payload
	SIZE_T	ObfuscatedPayloadSize = NULL;
	PBYTE	ObfuscatedPayloadBuffer = NULL;

	printf("[i] Obfuscating Payload ... ");
	if (!Obfuscate(RawPayloadBuffer, RawPayloadSize, &ObfuscatedPayloadBuffer, &ObfuscatedPayloadSize)) {
		return -1;
	}
	printf("[+] DONE \n");
	printf("\t>>> Obfuscated Payload Size : %ld \n\t>>> Obfuscated Payload Located At : 0x%p \n", ObfuscatedPayloadSize, ObfuscatedPayloadBuffer);

	// Write The Obfuscated Payload into Output File
	printf("[i] Writing The Obfuscated Payload ...");
	if (!WritePayloadFile(argv[1], ObfuscatedPayloadBuffer, ObfuscatedPayloadSize)) {
		return -1;
	}
	printf("[+] DONE \n");

	// Exit
	return 0;
}