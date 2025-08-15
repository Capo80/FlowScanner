# Linux self-injector

## Methodology

1. Generate shellcode inside `shellcode.h` (variable name should be `shellcode`)
1. Edit `crypto.c` and modify the encryption key (Note: MUST BE EXACTLY 8 bytes)
2. `make encrypt`
3. Save the encrypted shellcode: `./encrypt > shellcode_enc.h`
4. Check for possible errors in `shellcode_enc.h`
5. `make self-inject`
6. Execute the self-injector: `./self-inject`