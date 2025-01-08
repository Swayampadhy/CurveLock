#pragma once

#include <Windows.h>

// Function to get the file size
#ifndef HELPER_H
#define HELPER_H

// Padding and reducing entropy of payload
#define BUFF_SIZE 0X04
#define NULL_BYTES 0X01
#define KEY_SIZE 0x10

// Structure Of Payload Linked List
struct LINKED_LIST;
typedef struct _LINKED_LIST {
	BYTE pBuffer[BUFF_SIZE];   // Buffer to store the data
	BYTE pNull[NULL_BYTES];    // Buffer to store the NULL bytes
	INT ID;                    // ID of the buffer
	struct LINKED_LIST* Next; // Pointer to the next buffer
}LINKED_LIST, *PLINKED_LIST;

// Serialized Size of each node
#define SERIALIZED_SIZE (BUFF_SIZE + NULL_BYTES + sizeof(INT))

typedef enum SORT_TYPE {
	SORT_BY_ID,
	SORT_BY_BUFFER
};

// set the 'sPayloadSize' variable to be equal to the next nearest number that is multiple of 'N'
#define NEAREST_MULTIPLE(sPayloadSize, N)(SIZE_T)((SIZE_T)sPayloadSize + (int)N - ((SIZE_T)sPayloadSize % (int)N))

// Function Prototypes from EntropyReducer Obfuscator

BOOL WritePayloadFile(IN PSTR cFileInput, IN LPCVOID pPayloadData, IN SIZE_T Size);
BOOL ReadPayloadFile(IN PCSTR cFileInput, OUT PBYTE* pPayloadData, OUT PSIZE_T sPayloadSize);
BOOL InitializePayloadList(IN PBYTE pPayload, IN OUT PSIZE_T sPayloadSize, OUT PLINKED_LIST* ppLinkedList);
PLINKED_LIST InsertAtTheEnd(IN OUT PLINKED_LIST LinkedList, IN PBYTE pBuffer, IN INT ID);
VOID MergeSort(PLINKED_LIST* top, enum SORT_TYPE eType);

#endif // !HELPER_Hs