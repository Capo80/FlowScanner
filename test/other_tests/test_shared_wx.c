#include <stdio.h>
#include <stdlib.h>
#include <sys/mman.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <string.h>

int global_var = 100;

void __attribute__((aligned(4096))) function(void *main_var, int pid)
{
    int sum = 0;

    for (int i = 0; i < 10; i++)
    {
        sum += i;
    }

    if (pid == 0)
        (*(int *)main_var) += 1;
    else
        (*(int *)main_var) += 2;

    return;
}

int __attribute__((aligned(4096))) main()
{

    int main_var = 50;
    pid_t pid = -1;
    char ret = 0xC3;

    size_t size = (char *)main - (char *)function;

    printf("Function orig address: %lx\n", (unsigned long)function);

    printf("Size: %ld\n", size);

    /**
     * MAP_SHARED
              Share this mapping.  Updates to the mapping are visible to other processes mapping the
              same region, and (in the case of file-backed mappings) are carried through to the  un‐
              derlying file.  (To precisely control when updates are carried through to the underly‐
              ing file requires the use of msync(2).)
    */

    char *addr = mmap(NULL, 4096, PROT_READ | PROT_WRITE | PROT_EXEC, MAP_ANONYMOUS | MAP_SHARED, -1, 0);

    if (addr == MAP_FAILED)
    {
        perror("mmap");
        exit(EXIT_FAILURE);
    }

    printf("Memory allocated at %p\n", addr);

    memcpy(addr, function, size);

    printf("Parent process: global_var = %d, main_var = %d\n", global_var, main_var);

    void (*jump_to)(void *, int) = (void (*)(void *, int))addr;

    pid = fork();

    printf("PID: %d\n", pid);

    if (pid < 0)
    {
        perror("fork");
        exit(EXIT_FAILURE);
    }
    else if (pid == 0)
    {
        jump_to(&main_var, pid);
        printf("Child process: global_var = %d, main_var = %d\n", global_var, main_var);
    }
    else
    {
        sleep(1);
        memcpy(addr, &ret, 1); // 0xc3 is the opcode for ret
        jump_to(&main_var, pid);
        printf("Parent process: global_var = %d, main_var = %d\n", global_var, main_var);
        waitpid(pid, NULL, 0);
    }

    munmap(addr, size);

    return 0;
}