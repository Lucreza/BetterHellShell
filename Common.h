
#include <Windows.h>

#ifndef COMMON_H
#define COMMON_H




// to help identifying user input
#define HEADER					0x001
#define MAIN_OPEN				0x111
#define MAIN_CLOSE				0x112
#define SIZE_INI				0x221
#define AESENCRYPTION_PREMAIN	0x222
#define AESENCRYPTION_MAIN		0x223
#define RC4ENCRYPTION_PREMAIN	0x333
#define RC4ENCRYPTION_MAIN		0x334
#define XORENCRYPTION_PREMAIN	0x444
#define XORENCRYPTION_MAIN		0x445
#define IPV4FUSCATION_PREMAIN	0x555
#define IPV4FUSCATION_MAIN		0x556
#define IPV6FUSCATION_PREMAIN	0x666
#define IPV6FUSCATION_MAIN		0x667
#define MACFUSCATION_PREMAIN	0x777
#define MACFUSCATION_MAIN		0x778
#define UUIDFUSCATION_PREMAIN	0x888
#define UUIDFUSCATION_MAIN		0x889


// to help working with encryption algorithms
#define RC4KEYSIZE				16
#define XORKEYSIZE				16

#define AESKEYSIZE				32
#define AESIVSIZE				16




//-------------------------------------------------------------------------------------------------------------------------------
// 
// from IO.c
// read file from disk 
BOOL ReadPayloadFile(const char* FileInput, PDWORD sPayloadSize, unsigned char** pPayloadData);
//-------------------------------------------------------------------------------------------------------------------------------




//-------------------------------------------------------------------------------------------------------------------------------
// 
// from StringFunctions.c
// print the decryption / deobfuscation function (as a string) to the screen
VOID PrintDecodeFunctionality(IN INT TYPE);
//-------------------------------------------------------------------------------------------------------------------------------




//-------------------------------------------------------------------------------------------------------------------------------
// 
// from Encryption.c
// generate random bytes of size "sSize"
VOID GenerateRandomBytes(PBYTE pByte, SIZE_T sSize);
// print the input buffer as a hex char array (c syntax)
VOID PrintHexData(LPCSTR Name, PBYTE Data, SIZE_T Size);
//-------------------------------------------------------------------------------------------------------------------------------




//-------------------------------------------------------------------------------------------------------------------------------
// 
// from Encryption.c
// wrapper function for InstallAesEncryption that make things easier
BOOL AESEncryption(PBYTE pPayload, DWORD dwPayloadSize, struct AES_ctx* ctx, PVOID* ppCipherText, DWORD* pCipherTextSize);
// do the rc4 encryption
BOOL Rc4EncryptionViSystemFunc032(IN PBYTE pRc4Key, IN PBYTE pPayloadData, IN DWORD dwRc4KeySize, IN DWORD sPayloadSize);
//-------------------------------------------------------------------------------------------------------------------------------




//-------------------------------------------------------------------------------------------------------------------------------
// 
// from Obfuscation.c
// generate the UUid output representation of the shellcode
BOOL GenerateUuidOutput(unsigned char* pShellcode, SIZE_T ShellcodeSize);
// generate the Mac output representation of the shellcode
BOOL GenerateMacOutput(unsigned char* pShellcode, SIZE_T ShellcodeSize);
// generate the ipv6 output representation of the shellcode
BOOL GenerateIpv6Output(unsigned char* pShellcode, SIZE_T ShellcodeSize);
// generate the ipv4 output representation of the shellcode
BOOL GenerateIpv4Output(unsigned char* pShellcode, SIZE_T ShellcodeSize);
//-------------------------------------------------------------------------------------------------------------------------------




#endif // !COMMON_H
