#include <Windows.h>
#include <stdio.h>

#include "Common.h"


// Function takes in 16 raw bytes and returns them in a UUID string format
char* GenerateUuid(int a, int b, int c, int d, int e, int f, int g, int h, int i, int j, int k, int l, int m, int n, int o, int p) {
	// Dynamically allocate space for the UUID string
	char* result = (char*)malloc(128);  // Allocate enough space for the UUID string

	// Ensure that allocation succeeded
	if (result == NULL) {
		return NULL;  // Return NULL in case of memory allocation failure
	}

	// Each UUID segment
	char Output0[32], Output1[32], Output2[32], Output3[32];

	// Generating output0 from the first 4 bytes
	sprintf_s(Output0, sizeof(Output0), "%0.2X%0.2X%0.2X%0.2X", d, c, b, a);

	// Generating output1 from the second 4 bytes
	sprintf_s(Output1, sizeof(Output1), "%0.2X%0.2X-%0.2X%0.2X", f, e, h, g);

	// Generating output2 from the third 4 bytes
	sprintf_s(Output2, sizeof(Output2), "%0.2X%0.2X-%0.2X%0.2X", i, j, k, l);

	// Generating output3 from the last 4 bytes
	sprintf_s(Output3, sizeof(Output3), "%0.2X%0.2X%0.2X%0.2X", m, n, o, p);

	// Combining Output0,1,2,3 to generate the UUID
	sprintf_s(result, 128, "%s-%s-%s%s", Output0, Output1, Output2, Output3);

	return result;  // Return the dynamically allocated string
}





// generate the UUid output representation of the shellcode
BOOL GenerateUuidOutput(unsigned char* pShellcode, SIZE_T ShellcodeSize) {
	// If the shellcode buffer is null or the size is not a multiple of 16, exit
	if (pShellcode == NULL || ShellcodeSize == NULL || ShellcodeSize % 16 != 0) {
		return FALSE;
	}
	printf("char* UuidArray[%d] = { \n\t", (int)(ShellcodeSize / 16));

	// We will read one shellcode byte at a time, when the total is 16, begin generating the UUID string
	// The variable 'c' is used to store the number of bytes read. By default, starts at 16.
	int c = 16, counter = 0;
	char* UUID = NULL;

	for (int i = 0; i < ShellcodeSize; i++) {
		// Track the number of bytes read and when they reach 16 we enter this if statement to begin generating the UUID string
		if (c == 16) {
			counter++;

			// Generating the UUID string from 16 bytes which begin at i until [i + 15]
			UUID = GenerateUuid(
				pShellcode[i], pShellcode[i + 1], pShellcode[i + 2], pShellcode[i + 3],
				pShellcode[i + 4], pShellcode[i + 5], pShellcode[i + 6], pShellcode[i + 7],
				pShellcode[i + 8], pShellcode[i + 9], pShellcode[i + 10], pShellcode[i + 11],
				pShellcode[i + 12], pShellcode[i + 13], pShellcode[i + 14], pShellcode[i + 15]
			);
			if (i == ShellcodeSize - 16) {

				// Printing the last UUID string
				printf("\"%s\"", UUID);
				break;
			}
			else {
				// Printing the UUID string
				printf("\"%s\", ", UUID);
			}

			free(UUID);
			c = 1;
			// Optional: To beautify the output on the console
			if (counter % 3 == 0) {
				printf("\n\t");
			}

		}
		else {
			c++;
		}
	}
	printf("\n};\n\n");
	printf("#define NumberOfElements %d\n\n\n", counter);
	return TRUE;
}



// taking input raw bytes and returning them in mac string format

char* GenerateMAC(int a, int b, int c, int d, int e, int f) {
	static char result[64];  // Static buffer to store the result

	// Format the MAC address as a string (e.g., "XX-XX-XX-XX-XX-XX")
	sprintf_s(result, sizeof(result), "%0.2X-%0.2X-%0.2X-%0.2X-%0.2X-%0.2X", a, b, c, d, e, f);

	return result;  // Return the formatted MAC address
}

// generate the Mac output representation of the shellcode
BOOL GenerateMacOutput(unsigned char* pShellcode, SIZE_T ShellcodeSize) {

    // Check if shellcode is null or if size is not a multiple of 6
    if (pShellcode == NULL || ShellcodeSize == 0 || ShellcodeSize % 6 != 0) {
        printf("[Error] Invalid shellcode or size.\n");
        return FALSE;
    }

    printf("char* MacArray[] = { \n\t");

    int C = 0;  // Counter for the number of MAC addresses printed
    char* Mac = NULL;

    // Iterate over the shellcode to process every 6 bytes (representing one MAC address)
    for (int i = 0; i < ShellcodeSize; i += 6) {
        // Generate a MAC address from the next 6 bytes
        Mac = GenerateMAC(pShellcode[i], pShellcode[i + 1], pShellcode[i + 2], pShellcode[i + 3], pShellcode[i + 4], pShellcode[i + 5]);

        // Print the MAC address
        if (i == ShellcodeSize - 6) {
            // If it's the last MAC address, don't print a comma
            printf("\"%s\"", Mac);
        } else {
            // Print the MAC address followed by a comma
            printf("\"%s\", ", Mac);
        }

        // Increase the counter and print a newline after every 6 MAC addresses for formatting
        C++;
        if (C % 6 == 0) {
            printf("\n\t");
        }
    }

    // Print the closing bracket and define the number of elements
    printf("\n};\n\n");
    printf("#define NumberOfElements %d\n\n\n", C);

    fflush(stdout);  // Ensure all output is written to stdout immediately
    return TRUE;
}




// taking input raw bytes and returning them in ipv6 string format
char* GenerateIpv6(int a, int b, int c, int d, int e, int f, int g, int h,
	int i, int j, int k, int l, int m, int n, int o, int p) {

	static char result[128];  // Static buffer to hold the result

	// Formatting each 16-bit section of the IPv6 address
	sprintf_s(result, sizeof(result), "%0.2X%0.2X:%0.2X%0.2X:%0.2X%0.2X:%0.2X%0.2X:%0.2X%0.2X:%0.2X%0.2X:%0.2X%0.2X:%0.2X%0.2X",
		a, b, c, d, e, f, g, h, i, j, k, l, m, n, o, p);

	return result;  // Return the formatted string
}


// generate the ipv6 output representation of the shellcode
BOOL GenerateIpv6Output(unsigned char* pShellcode, SIZE_T ShellcodeSize) {

	// Check if the shellcode is NULL or if the size is not a multiple of 16 (IPv6 address length)
	if (pShellcode == NULL || ShellcodeSize == 0 || ShellcodeSize % 16 != 0) {
		printf("[Error] Invalid shellcode or size.\n");
		return FALSE;
	}

	printf("char* Ipv6Array[] = { \n\t");

	int C = 0;  // Counter for the number of IPs printed
	char* IP = NULL;

	// Iterate over the shellcode to process every 16 bytes (representing one IPv6 address)
	for (int i = 0; i < ShellcodeSize; i += 16) {
		// Generate an IPv6 address from the next 16 bytes
		IP = GenerateIpv6(
			pShellcode[i], pShellcode[i + 1], pShellcode[i + 2], pShellcode[i + 3],
			pShellcode[i + 4], pShellcode[i + 5], pShellcode[i + 6], pShellcode[i + 7],
			pShellcode[i + 8], pShellcode[i + 9], pShellcode[i + 10], pShellcode[i + 11],
			pShellcode[i + 12], pShellcode[i + 13], pShellcode[i + 14], pShellcode[i + 15]
		);

		// Print the IPv6 address
		if (i == ShellcodeSize - 16) {
			// If it's the last IP, don't print a comma
			printf("\"%s\"", IP);
		}
		else {
			// Print the IP followed by a comma
			printf("\"%s\", ", IP);
		}

		// Increase the counter and print a newline after every 3 IPs for formatting
		C++;
		if (C % 3 == 0) {
			printf("\n\t");
		}
	}

	// Print the closing bracket and define the number of elements
	printf("\n};\n\n");
	printf("#define NumberOfElements %d\n\n\n", C);

	return TRUE;
}


// Generate an IPv4 string from 4 integers (bytes)
char* GenerateIpv4(int a, int b, int c, int d) {
	static char Output[16];  // A static buffer to hold the resulting string
	// Combine the 4 bytes into a string representation of the IPv4 address
	sprintf_s(Output, sizeof(Output), "%d.%d.%d.%d", a, b, c, d);
	return Output;  // Return the string (safe because it's static)
}



// Generate the IPv4 output representation of the shellcode
BOOL GenerateIpv4Output(unsigned char* pShellcode, SIZE_T ShellcodeSize) {

	// Check if the shellcode is NULL or if the size is not a multiple of 4
	if (pShellcode == NULL || ShellcodeSize == 0 || ShellcodeSize % 4 != 0) {
		printf("[Error] Invalid shellcode or size.\n");
		return FALSE;
	}

	printf("char* Ipv4Array[] = { \n\t");

	int C = 0;  // Counter for the number of IPs printed
	char* IP = NULL;

	// Iterate over the shellcode to process every 4 bytes (representing one IPv4 address)
	for (int i = 0; i < ShellcodeSize; i += 4) {
		// Generate an IPv4 address from the next 4 bytes
		IP = GenerateIpv4(pShellcode[i], pShellcode[i + 1], pShellcode[i + 2], pShellcode[i + 3]);

		// Print the IPv4 address
		if (i == ShellcodeSize - 4) {
			// If it's the last IP, don't print a comma
			printf("\"%s\"", IP);
		}
		else {
			// Print the IP followed by a comma
			printf("\"%s\", ", IP);
		}

		// Increase the counter and print a newline after every 8 IPs for formatting
		C++;
		if (C % 8 == 0) {
			printf("\n\t");
		}
	}

	// Print the closing bracket and define the number of elements
	printf("\n};\n\n");
	printf("#define NumberOfElements %d\n\n\n", C);

	return TRUE;
}


