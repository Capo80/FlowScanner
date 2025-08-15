#include <stdio.h>
#include <pthread.h>

#define NUM_THREADS 5

void *__attribute__((aligned(4096))) sum(void *arg)
{
    int sum = 0;
    for (int i = 0; i <= 10; i++)
    {
        sum += i;
    }
    printf("Sum: %d\n", sum);
    return NULL;
}

void *print_hello(void *arg)
{
    printf("Hello, world!\n");
    return NULL;
}

void *print_thread_id(void *arg)
{
    printf("Thread ID: %lu\n", pthread_self());
    return NULL;
}

void *print_numbers(void *arg)
{
    for (int i = 0; i < 10; i++)
    {
        printf("%d ", i);
    }
    printf("\n");
    return NULL;
}

void *print_letters(void *arg)
{
    for (char c = 'a'; c <= 'j'; c++)
    {
        printf("%c ", c);
    }
    printf("\n");
    return NULL;
}

int __attribute__((aligned(4096))) main()
{

    printf("MAIN ADDRESS = %lx\n", (unsigned long)main);
    printf("SUM ADDRESS = %lx\n", (unsigned long)sum);
    printf("PRINT_HELLO ADDRESS = %lx\n", (unsigned long)print_hello);
    printf("PRINT_THREAD_ID ADDRESS = %lx\n", (unsigned long)print_thread_id);
    printf("PRINT_NUMBERS ADDRESS = %lx\n", (unsigned long)print_numbers);
    printf("PRINT_LETTERS ADDRESS = %lx\n", (unsigned long)print_letters);

    pthread_t threads[NUM_THREADS];

    pthread_create(&threads[0], NULL, sum, NULL);
    pthread_create(&threads[1], NULL, print_hello, NULL);
    pthread_create(&threads[2], NULL, print_thread_id, NULL);
    pthread_create(&threads[3], NULL, print_numbers, NULL);
    pthread_create(&threads[4], NULL, print_letters, NULL);

    for (int i = 0; i < 5; i++)
    {
        sum(NULL);
        print_hello(NULL);
        print_thread_id(NULL);
        print_numbers(NULL);
        print_letters(NULL);
    }

    for (int i = 0; i < NUM_THREADS; i++)
    {
        pthread_join(threads[i], NULL);
    }

    return 0;
}