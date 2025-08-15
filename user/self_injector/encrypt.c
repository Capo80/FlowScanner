#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "crypt.h"
#include "shellcode.h"

int main() {
    size_t shellcode_len = sizeof(shellcode);

    void *mem = malloc(shellcode_len);

    if (NULL == mem) {
        perror("Error while allocating memory");
        exit(EXIT_FAILURE);
    }

    memcpy(mem, shellcode, shellcode_len);

    //printf("key len is %ld\n", sizeof(key));

    _XOR(mem, shellcode_len, key, sizeof(key));

    printf("unsigned char shellcode[] = \"");
    for (size_t i = 0; i < shellcode_len; i++) {
        printf("\\x%02hhx", (char) ((char *)(mem))[i]);
    }
    printf("\";\n");

}