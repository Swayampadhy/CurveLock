#pragma once

#include <Windows.h>

#ifndef HELPER_H
#define HELPER_H

// these values should be the same as that in EntropyReducer - "common.h"
// if you modified them there, you need to modify these here as well
#define BUFF_SIZE				0x04			
#define NULL_BYTES				0x01			

// Structure to hold the linked list
struct LINKED_LIST;
typedef struct _LINKED_LIST
{
    BYTE					pBuffer[BUFF_SIZE];	    // payload's bytes
    BYTE					pNull[NULL_BYTES];	    // null padded bytes
    INT						ID;						// node id
    struct LINKED_LIST* Next;					    // next node pointer	

}LINKED_LIST, * PLINKED_LIST;

// this will represent the seraizlized size of one node
#define SERIALIZED_SIZE			(BUFF_SIZE + NULL_BYTES + sizeof(INT))	
typedef enum SORT_TYPE {
    SORT_BY_ID,
    SORT_BY_BUFFER
};

// set the 'sPayloadSize' variable to be equal to the next nearest number that is multiple of 'N'
#define NEAREST_MULTIPLE(sPayloadSize, N)(SIZE_T)((SIZE_T)sPayloadSize + (int)N - ((SIZE_T)sPayloadSize % (int)N))

// Deobfuscation function Prototype
BOOL Deobfuscate(IN PBYTE pFuscatedBuff, IN SIZE_T sFuscatedSize, OUT PBYTE* ptPayload, OUT PSIZE_T psSize);


#endif // !HELPER_H