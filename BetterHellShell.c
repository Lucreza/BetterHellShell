#include <Windows.h>
#include <stdio.h>
#include <string.h>

#include "Common.h"
#include "aes.h"

// Define the supported encryption methods
CHAR* SupportedEncryption[] = { "none", "xor", "aes", "rc4" };

// Define the supported obfuscation methods
CHAR* SupportedObfuscation[] = { "none", "mac", "ipv4", "ipv6", "uuid" };

// Function to append padding to the input payload, ensuring it is a multiple of the given size
BOOL AppendInputPayload(IN INT MultipleOf, IN PBYTE pPayload, IN DWORD dwPayloadSize, OUT PBYTE* ppAppendedPayload, OUT DWORD* pAppendedPayloadSize) {
    PBYTE Append = NULL;
    DWORD AppendSize = NULL;

    // Calculate the new payload size to be a multiple of 'MultipleOf'
    AppendSize = dwPayloadSize + MultipleOf - (dwPayloadSize % MultipleOf);

    // Allocate memory for the new padded payload
    Append = (PBYTE)HeapAlloc(GetProcessHeap(), 0, AppendSize);
    if (Append == NULL)
        return FALSE; // Return FALSE if memory allocation fails

    // Fill the allocated memory with NOPs (0x90) for padding
    memset(Append, 0x90, AppendSize);

    // Copy the original payload into the padded memory
    memcpy(Append, pPayload, dwPayloadSize);

    // Return the new padded payload and its size
    *ppAppendedPayload = Append;
    *pAppendedPayloadSize = AppendSize;

    return TRUE; // Return TRUE if successful
}

// Print the help message explaining how to use the program
INT PrintHelp(IN CHAR* _Argv0) {
    printf("\t\t\t ###########################################################\n");
    printf("\t\t\t #            BetterHellShell - Made By @Lucreza           #\n");
    printf("\t\t\t #       Inspired By HellShell from @NUL0x4C | @mrd0x      #\n");
    printf("\t\t\t ###########################################################\n\n");

    // Print usage instructions
    printf("[!] Usage: %s <Input Payload FileName> <Encryption Option> <Obfuscation Option>\n", _Argv0);

    // Print supported encryption types
    printf("[i] Supported encryption types:\n");
    printf("\t1.>>> \"none\" ::: No encryption, only obfuscation\n");
    printf("\t2.>>> \"xor\"  ::: XOR encryption with a key\n");
    printf("\t3.>>> \"aes\"  ::: AES encryption with random key and IV\n");
    printf("\t4.>>> \"rc4\"  ::: RC4 encryption with random key\n");

    // Print supported obfuscation types
    printf("\n[i] Supported obfuscation types:\n");
    printf("\t1.>>> \"none\" ::: No obfuscation\n");
    printf("\t2.>>> \"mac\"  ::: MAC address obfuscation\n");
    printf("\t3.>>> \"ipv4\" ::: IPv4 address obfuscation\n");
    printf("\t4.>>> \"ipv6\" ::: IPv6 address obfuscation\n");
    printf("\t5.>>> \"uuid\" ::: UUID obfuscation\n");

    printf("\n\n[i] ");
    system("PAUSE");  // Pause the program and wait for user input before proceeding
    return -1; // Return error code if help is printed
}

// Main function
int main(int argc, char* argv[]) {
    // Flags to check if the provided encryption and obfuscation types are supported
    BOOL bSupportedEncryption = FALSE;
    BOOL bSupportedObfuscation = FALSE;

    // Variables to hold the input payload and its size
    PBYTE pPayloadInput = NULL;
    DWORD dwPayloadSize = NULL;

    // Variables for encrypted payload (used for AES/RC4 encryption)
    PVOID pCipherText = NULL;
    DWORD dwCipherSize = NULL;

    // Validate the number of arguments passed to the program
    if (argc != 4) {
        return PrintHelp(argv[0]); // Print help message if the number of arguments is incorrect
    }

    // Check if the encryption type provided is valid
    for (size_t i = 0; i < 4; i++) {
        if (strcmp(argv[2], SupportedEncryption[i]) == 0) {
            bSupportedEncryption = TRUE;
            break; // Exit loop if encryption type is valid
        }
    }
    if (!bSupportedEncryption) {
        printf("<<<!>>> \"%s\" is not a valid encryption type <<<!>>>\n", argv[2]);
        return PrintHelp(argv[0]); // Print help message if the encryption type is invalid
    }

    // Check if the obfuscation type provided is valid
    for (size_t i = 0; i < 5; i++) {
        if (strcmp(argv[3], SupportedObfuscation[i]) == 0) {
            bSupportedObfuscation = TRUE;
            break; // Exit loop if obfuscation type is valid
        }
    }
    if (!bSupportedObfuscation) {
        printf("<<<!>>> \"%s\" is not a valid obfuscation type <<<!>>>\n", argv[3]);
        return PrintHelp(argv[0]); // Print help message if the obfuscation type is invalid
    }

    // Read the input payload from the file
    if (!ReadPayloadFile(argv[1], &dwPayloadSize, &pPayloadInput)) {
        return -1; // Return error if the file cannot be read
    }

    // Check if both encryption and obfuscation types are "none"
    if (strcmp(argv[2], "none") == 0 && strcmp(argv[3], "none") == 0) {
        printf("<<<!>>> \"%s\" and \"%s\" cannot be used at the same time <<<!>>>\n", argv[2], argv[3]);
        return PrintHelp(argv[0]); // Print help message if both are "none"
    }

    // Print initial decoding functionality
    PrintDecodeFunctionality(HEADER);

    // Handle the chosen encryption type
    if (strcmp(argv[2], "none") == 0) {
        // No encryption, only obfuscation (no action required)
    }
    else if (strcmp(argv[2], "xor") == 0) {
        // XOR encryption: Generate a random key and encrypt the payload
        BYTE KEY[XORKEYSIZE], KEY2[XORKEYSIZE];
        srand(time(NULL)); // Seed the random number generator
        GenerateRandomBytes(KEY, XORKEYSIZE); // Generate a random XOR key

        // Perform XOR encryption
        if (!XorEncryption(pPayloadInput, dwPayloadSize, (PBYTE)KEY, XORKEYSIZE, &pCipherText, &dwCipherSize)) {
            HeapFree(GetProcessHeap(), 0, pPayloadInput); // Free memory if encryption fails
            return -1; // Return error if encryption fails
        }

        // Copy the key for later use (printing)
        memcpy(KEY2, KEY, AESKEYSIZE);

        // Print encryption details
        PrintDecodeFunctionality(XORENCRYPTION_PREMAIN);
        PrintHexData("XorKey", KEY2, XORKEYSIZE);

        // Update the payload with the encrypted data
        pPayloadInput = pCipherText;
        dwPayloadSize = dwCipherSize;
    }
    else if (strcmp(argv[2], "rc4") == 0) {
        // RC4 encryption: Generate a random key and encrypt the payload
        BYTE KEY[RC4KEYSIZE], KEY2[RC4KEYSIZE];
        srand(time(NULL)); // Seed the random number generator
        GenerateRandomBytes(KEY, RC4KEYSIZE); // Generate a random RC4 key

        memcpy(KEY2, KEY, AESKEYSIZE);

        // Perform RC4 encryption
        if (!Rc4EncryptionViSystemFunc032((PBYTE)KEY, pPayloadInput, RC4KEYSIZE, dwPayloadSize)) {
            HeapFree(GetProcessHeap(), 0, pPayloadInput); // Free memory if encryption fails
            return -1; // Return error if encryption fails
        }

        // Print encryption details
        PrintDecodeFunctionality(RC4ENCRYPTION_PREMAIN);
        PrintHexData("Rc4Key", KEY2, RC4KEYSIZE);
    }
    else if (strcmp(argv[2], "aes") == 0) {
        // AES encryption: Generate a random key and IV, then encrypt the payload
        struct AES_ctx ctx;
        BYTE pKey[AESKEYSIZE], pKey2[AESKEYSIZE];
        BYTE pIv[AESIVSIZE], pIv2[AESIVSIZE];

        srand(time(NULL)); // Seed the random number generator
        GenerateRandomBytes(pKey, AESKEYSIZE); // Generate the AES key

        srand(time(NULL) ^ pKey[0]); // Seed for IV generation
        GenerateRandomBytes(pIv, AESIVSIZE); // Generate the AES IV

        // Save the original key and IV for later printing
        memcpy(pKey2, pKey, AESKEYSIZE);
        memcpy(pIv2, pIv, AESIVSIZE);

        // Initialize AES context with the generated key and IV
        AES_init_ctx_iv(&ctx, pKey, pIv);

        // Perform AES encryption
        if (!AESEncryption(pPayloadInput, dwPayloadSize, &ctx, &pCipherText, &dwCipherSize)) {
            HeapFree(GetProcessHeap(), 0, pPayloadInput); // Free memory if encryption fails
            return -1; // Return error if encryption fails
        }

        // Print encryption details
        PrintDecodeFunctionality(AESENCRYPTION_PREMAIN);
        PrintHexData("AesKey", pKey2, AESKEYSIZE);
        PrintHexData("AesIv", pIv2, AESIVSIZE);

        // Update the payload with the encrypted data
        pPayloadInput = pCipherText;
        dwPayloadSize = dwCipherSize;
    }

    // Handle the chosen obfuscation type
    if (strcmp(argv[3], "none") == 0) {
        // No obfuscation, only encryption (no action required)
    }
    else if (strcmp(argv[3], "mac") == 0) {
        // MAC address obfuscation: Pad the payload to be a multiple of 6 bytes
        if (dwPayloadSize % 6 != 0) {
            if (!AppendInputPayload(6, pPayloadInput, dwPayloadSize, &pPayloadInput, &dwPayloadSize)) {
                HeapFree(GetProcessHeap(), 0, pPayloadInput); // Free memory if padding fails
                return -1; // Return error if padding fails
            }
        }
        // Generate and print MAC address obfuscated output
        if (!GenerateMacOutput(pPayloadInput, dwPayloadSize)) {
            HeapFree(GetProcessHeap(), 0, pPayloadInput); // Free memory if output generation fails
            return -1; // Return error if output generation fails
        }
        PrintDecodeFunctionality(MACFUSCATION_PREMAIN);
    }
    else if (strcmp(argv[3], "ipv4") == 0) {
        // IPv4 address obfuscation: Pad the payload to be a multiple of 4 bytes
        if (dwPayloadSize % 4 != 0) {
            if (!AppendInputPayload(4, pPayloadInput, dwPayloadSize, &pPayloadInput, &dwPayloadSize)) {
                HeapFree(GetProcessHeap(), 0, pPayloadInput); // Free memory if padding fails
                return -1; // Return error if padding fails
            }
        }
        // Generate and print IPv4 address obfuscated output
        if (!GenerateIpv4Output(pPayloadInput, dwPayloadSize)) {
            HeapFree(GetProcessHeap(), 0, pPayloadInput); // Free memory if output generation fails
            return -1; // Return error if output generation fails
        }
        PrintDecodeFunctionality(IPV4FUSCATION_PREMAIN);
    }
    else if (strcmp(argv[3], "ipv6") == 0) {
        // IPv6 address obfuscation: Pad the payload to be a multiple of 16 bytes
        if (dwPayloadSize % 16 != 0) {
            if (!AppendInputPayload(16, pPayloadInput, dwPayloadSize, &pPayloadInput, &dwPayloadSize)) {
                HeapFree(GetProcessHeap(), 0, pPayloadInput); // Free memory if padding fails
                return -1; // Return error if padding fails
            }
        }
        // Generate and print IPv6 address obfuscated output
        if (!GenerateIpv6Output(pPayloadInput, dwPayloadSize)) {
            HeapFree(GetProcessHeap(), 0, pPayloadInput); // Free memory if output generation fails
            return -1; // Return error if output generation fails
        }
        PrintDecodeFunctionality(IPV6FUSCATION_PREMAIN);
    }
    else if (strcmp(argv[3], "uuid") == 0) {
        // UUID obfuscation: Pad the payload to be a multiple of 16 bytes
        if (dwPayloadSize % 16 != 0) {
            if (!AppendInputPayload(16, pPayloadInput, dwPayloadSize, &pPayloadInput, &dwPayloadSize)) {
                HeapFree(GetProcessHeap(), 0, pPayloadInput); // Free memory if padding fails
                return -1; // Return error if padding fails
            }
        }
        // Generate and print UUID obfuscated output
        if (!GenerateUuidOutput(pPayloadInput, dwPayloadSize)) {
            HeapFree(GetProcessHeap(), 0, pPayloadInput); // Free memory if output generation fails
            return -1; // Return error if output generation fails
        }
        PrintDecodeFunctionality(UUIDFUSCATION_PREMAIN);
    }

    // Main Print Output Section
    PrintDecodeFunctionality(MAIN_OPEN);
    if (strcmp(argv[3], "ipv4") == 0) {
        PrintDecodeFunctionality(IPV4FUSCATION_MAIN);
    }
    else if (strcmp(argv[3], "ipv6") == 0) {
        PrintDecodeFunctionality(IPV6FUSCATION_MAIN);
    }
    else if (strcmp(argv[3], "uuid") == 0) {
        PrintDecodeFunctionality(UUIDFUSCATION_MAIN);
    }
    else if (strcmp(argv[3], "mac") == 0) {
        PrintDecodeFunctionality(MACFUSCATION_MAIN);
    }
    if (strcmp(argv[2], "aes") == 0) {
        if (strcmp(argv[3], "none") == 0) {
            PrintHexData("cipherText", pCipherText, dwCipherSize);
            PrintDecodeFunctionality(SIZE_INI);
        }
        PrintDecodeFunctionality(AESENCRYPTION_MAIN);
    }
    else if (strcmp(argv[2], "rc4") == 0) {
        if (strcmp(argv[3], "none") == 0) {
            PrintHexData("cipherText", pPayloadInput, dwPayloadSize);
            PrintDecodeFunctionality(SIZE_INI);
        }
        PrintDecodeFunctionality(RC4ENCRYPTION_MAIN);
    }
    else if (strcmp(argv[2], "xor") == 0) {
        if (strcmp(argv[3], "none") == 0) {
            PrintHexData("cipherText", pCipherText, dwCipherSize);
            PrintDecodeFunctionality(SIZE_INI);
        }
        PrintDecodeFunctionality(XORENCRYPTION_MAIN);
    }
    PrintDecodeFunctionality(MAIN_CLOSE); // Final output stage

    fflush(stdout); // Ensure all output is printed

    // Cleanup dynamically allocated memory
    if (pPayloadInput != NULL) {
        HeapFree(GetProcessHeap(), 0, pPayloadInput); // Free memory for the input payload
    }
    if (pCipherText != NULL) {
        HeapFree(GetProcessHeap(), 0, pCipherText); // Free memory for the cipher text if used
    }

    return 0; // Return success if no errors occurred
}
