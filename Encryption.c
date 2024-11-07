#include <Windows.h>
#include <stdio.h>
#include "aes.h"

#include "Common.h"

#define NT_SUCCESS(status)	        (((NTSTATUS)(status)) >= 0)


// this is what SystemFunction032 function take as a parameter for RC4
typedef struct
{
	DWORD	Length;
	DWORD	MaximumLength;
	PVOID	Buffer;

} USTRING;


// defining how does the function look - more on this structure in the api hashing part
typedef NTSTATUS(NTAPI* fnSystemFunction032)(
	struct USTRING* Img,
	struct USTRING* Key
	);

// Generate random bytes of size sSize
VOID GenerateRandomBytes(PBYTE pByte, SIZE_T sSize) {

	for (int i = 0; i < sSize; i++) {
		pByte[i] = (BYTE)rand() % 0xFF;
	}

}

// Function that will take a buffer, and copy it to another buffer that is a multiple of 16 in size
BOOL PaddBuffer(IN PBYTE InputBuffer, IN SIZE_T InputBufferSize, OUT PBYTE* OutputPaddedBuffer, OUT SIZE_T* OutputPaddedSize) {
	PBYTE PaddedBuffer = NULL;
	SIZE_T PaddedSize = 0;

	// Calculate the nearest multiple of 16 (AES block size)
	PaddedSize = InputBufferSize + 16 - (InputBufferSize % 16);

	// Allocate memory for the padded buffer
	PaddedBuffer = (PBYTE)HeapAlloc(GetProcessHeap(), 0, PaddedSize);
	if (!PaddedBuffer) {
		return FALSE; // Return false if allocation fails
	}

	// Initialize the allocated buffer to zero
	ZeroMemory(PaddedBuffer, PaddedSize);

	// Copy the original buffer into the padded buffer
	memcpy(PaddedBuffer, InputBuffer, InputBufferSize);

	// Save the results and return success
	*OutputPaddedBuffer = PaddedBuffer;
	*OutputPaddedSize = PaddedSize;

	return TRUE;
}

// print the input buffer as a hex char array (c syntax)
VOID PrintHexData(LPCSTR Name, PBYTE Data, SIZE_T Size) {

	printf("unsigned char %s[] = {", Name);

	for (int i = 0; i < Size; i++) {
		if (i % 16 == 0) {
			printf("\n\t");
		}
		if (i < Size - 1) {
			printf("0x%0.2X, ", Data[i]);
		}
		else {
			printf("0x%0.2X ", Data[i]);
		}
	}

	printf("};\n\n\n");

}


// AES Encryption function
BOOL AESEncryption(PBYTE pPayload, DWORD dwPayloadSize, struct AES_ctx* ctx, PVOID* ppCipherText, DWORD* pCipherTextSize) {
	PBYTE PaddedBuffer = NULL;
	SIZE_T PAddedSize = 0;

	// Check if padding is needed (payload size should be a multiple of 16)
	if (dwPayloadSize % 16 != 0) {
		// Padding the buffer to make its size a multiple of 16
		if (!PaddBuffer(pPayload, dwPayloadSize, &PaddedBuffer, &PAddedSize)) {
			return -1;  // Return error if padding fails
		}
		// Encrypt the padded buffer using AES CBC mode
		AES_CBC_encrypt_buffer(ctx, PaddedBuffer, PAddedSize);

		// Set the output parameters to the padded buffer and its size
		*ppCipherText = PaddedBuffer;
		*pCipherTextSize = PAddedSize;
		
	}
	else {
		// No padding required, encrypt the original buffer
		AES_CBC_encrypt_buffer(ctx, pPayload, dwPayloadSize);

		// Set the output parameters to the original payload and its size
		*ppCipherText = pPayload;
		*pCipherTextSize = dwPayloadSize;
	}

	return TRUE;  // Return success
}



// XOR encryption function (for simplicity)
BOOL XorEncryption(PBYTE pPayload, DWORD dwPayloadSize, PBYTE pKey, DWORD dwKeySize, PVOID* ppCipherText, DWORD* pCipherTextSize) {
	*ppCipherText = malloc(dwPayloadSize); // Allocate memory for the cipher text
	if (*ppCipherText == NULL) return FALSE;

	// XOR each byte of the payload with the key (repeating the key if necessary)
	for (DWORD i = 0; i < dwPayloadSize; i++) {
		((PBYTE)*ppCipherText)[i] = pPayload[i] ^ pKey[i % dwKeySize];
	}
	*pCipherTextSize = dwPayloadSize; // Set the cipher text size
	return TRUE;
}


// do the rc4 encryption
BOOL Rc4EncryptionViSystemFunc032(IN PBYTE pRc4Key, IN PBYTE pPayloadData, IN DWORD dwRc4KeySize, IN DWORD sPayloadSize) {

	// the return of SystemFunction032
	NTSTATUS	STATUS = NULL;

	// making 2 USTRING variables, 1 passed as key and one passed as the block of data to encrypt/decrypt
	USTRING		Key = { .Buffer = pRc4Key, 		.Length = dwRc4KeySize,		.MaximumLength = dwRc4KeySize },
		Img = { .Buffer = pPayloadData, 	.Length = sPayloadSize,		.MaximumLength = sPayloadSize };


	// since SystemFunction032 is exported from Advapi32.dll, we load it Advapi32 into the prcess, 
	// and using its return as the hModule parameter in GetProcAddress
	fnSystemFunction032 SystemFunction032 = (fnSystemFunction032)GetProcAddress(LoadLibraryA("Advapi32"), "SystemFunction032");

	// if SystemFunction032 calls failed it will return non zero value 
	if (!NT_SUCCESS(STATUS = SystemFunction032(&Img, &Key))) {
		printf("[!] SystemFunction032 FAILED With Error: 0x%0.8X \n", STATUS);
		return FALSE;
	}

	return TRUE;
}





