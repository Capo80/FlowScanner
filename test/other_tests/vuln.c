/* Compile with symbols: gcc -no-pie -fno-stack-protector vuln.c -o vuln */
/* Compile without symbols: gcc -s -no-pie -fno-stack-protector vuln.c -o vuln */
/* Enable ASLR: echo 2 > /proc/sys/kernel/randomize_va_space */ 

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

//nothing to see here
void nothing() {
    asm("pop %rdi; ret;");
}


int __attribute__((aligned(4096))) vuln() {
    char buf[80];
    int r;
    r = read(0, buf, 400);
    printf("\nRead %d bytes. buf is %s\n", r, buf);
    puts("No shell for you :(\n");
    return 0;
}

int  __attribute__((aligned(4096))) main(int argc, char *argv[]) {
    printf("Try to exec /bin/sh\n");
    vuln();

    vuln();
    return 0;
}
