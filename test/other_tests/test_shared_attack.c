#include <stdio.h>
#include <stdlib.h>
#include <sys/mman.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <string.h>

int __attribute__((aligned(4096))) attacker_function(char *wait_addr, int result)
{
    result = 1;
    return result;
}

int __attribute__((aligned(4096))) executor_main(char *wait_addr, int result)
{
    while (wait_addr[0] == 0) {
        result = 0;
    }

    return result;
}


int __attribute__((aligned(4096))) main()
{

    int main_var = 0;
    pid_t pid = -1;
    char ret = 0xC3;

    size_t size = (char *)main - (char *)executor_main;

    printf("Function orig address: %lx\n", (unsigned long)executor_main);

    printf("Size: %ld\n", size);

    /**
     * MAP_SHARED
              Share this mapping.  Updates to the mapping are visible to other processes mapping the
              same region, and (in the case of file-backed mappings) are carried through to the  un‐
              derlying file.  (To precisely control when updates are carried through to the underly‐
              ing file requires the use of msync(2).)
    */
    char *monitor = mmap(NULL, 4096, PROT_READ | PROT_WRITE | PROT_EXEC, MAP_ANONYMOUS | MAP_SHARED, -1, 0);
    char *executor_addr = mmap(NULL, 4096, PROT_READ | PROT_WRITE | PROT_EXEC, MAP_ANONYMOUS | MAP_SHARED, -1, 0);

    if (monitor == MAP_FAILED || executor_addr == MAP_FAILED)
    {
        perror("mmap");
        exit(EXIT_FAILURE);
    }

    printf("Memory allocated at %p\n", executor_addr);

    monitor[0] = 0;
    memcpy(executor_addr, executor_main, 4096);

    printf("Parent process: global_var = %d, main_var = %d\n", main_var);

    int (*jump_to)(char* , int) = (int (*)(char *, int))executor_addr;

    pid = fork();

    printf("PID: %d\n", pid);

    if (pid < 0)
    {
        perror("fork");
        exit(EXIT_FAILURE);
    }
    else if (pid == 0)
    {   

        printf("Child process: jumping in\n");
        int res = jump_to(monitor, main_var);
        printf("Child process: exited, return %d\n", res);
    }
    else
    {
        sleep(4);
        printf("Parent process: copy start\n");
        memcpy((executor_addr+31), (attacker_function+11), 23);
        printf("Parent process: copied new stuff\n");
        monitor[0] = 1;
        printf("Parent process: activated child\n");
        waitpid(pid, NULL, 0);
    }

    return 0;
}