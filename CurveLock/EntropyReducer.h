#pragma once

#include <Windows.h>

#ifndef HELPER_H
#define HELPER_H

// these values should be the same as that in Entropyreducer - "common.h"
// if you modified them there, you need to modify these here as well
#define BUFF_SIZE				0x04			
#define NULL_BYTES				0x01			


// Deobfuscation function Prototype
BOOL Deobfuscate(IN PBYTE pFuscatedBuff, IN SIZE_T sFuscatedSize, OUT PBYTE* ptPayload, OUT PSIZE_T psSize);


#endif // !HELPER_H