#ifndef _CRYPT_H
#define _CRYPT_H

extern unsigned char key[8];

void _XOR(unsigned char * data, size_t data_len, unsigned char * key, size_t key_len);

#endif