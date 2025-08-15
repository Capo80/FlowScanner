#include <stdio.h>
#include "crypt.h"

unsigned char key[]= "\x02\x01\x05\x07\x09\x10\x11\x0f";


void _XOR(unsigned char * data, size_t data_len, unsigned char * key, size_t key_len) {
    long unsigned int j;
    
    j = 0;
    for (long unsigned int i = 0; i < data_len; i++) {
        if (j == key_len - 1) j = 0;
        data[i] = data[i] ^ key[j];
        j++;
    }
}