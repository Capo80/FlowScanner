#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <unistd.h>
#include <stdint.h>

#define PAGE_SIZE 4096

// Raw RDTSC
static inline uint64_t get_cycles() {
    uint32_t lo, hi;
    __asm__ __volatile__ ("rdtsc" : "=a" (lo), "=d" (hi));
    return ((uint64_t)hi << 32) | lo;
}

int main(int argc, char* argv[]) {
    if (argc < 4) {
        printf("Usage: %s <jumps in K> <nops between> <iterations>\n", argv[0]);
        return -1;
    }

    long total_jumps = atol(argv[1]) * 1000;
    int nops_count = atoi(argv[2]);
    int iterations = atoi(argv[3]);

    int stride = 5 + nops_count;
    size_t requested_size = (total_jumps * stride) + 1;
    size_t mem_size = (requested_size + PAGE_SIZE - 1) & ~(PAGE_SIZE - 1);

    void *mem = mmap(NULL, mem_size, PROT_READ | PROT_WRITE | PROT_EXEC,
                     MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);

    if (mem == MAP_FAILED) {
        perror("mmap");
        return 1;
    }

    unsigned char *ptr = (unsigned char *)mem;
    for (long i = 0; i < total_jumps; i++) {
        size_t offset = i * stride;
        ptr[offset] = 0xE9; 
        int32_t disp = nops_count; 
        memcpy(&ptr[offset + 1], &disp, 4);
        if (nops_count > 0) memset(&ptr[offset + 5], 0x90, nops_count);
    }
    ptr[total_jumps * stride] = 0xC3;

    void (*jump_chain)() = (void (*)())mem;

    // Measurement loop
    uint64_t start = get_cycles();
    for (int i = 0; i < iterations; i++) {
        jump_chain();
    }
    uint64_t end = get_cycles();

    uint64_t elapsed = end - start;

    printf("Total Cycles: %lu\n", elapsed);
    printf("Total Jumps Executed: %ld\n", total_jumps * iterations);
    
    munmap(mem, mem_size);
    return 0;
}
