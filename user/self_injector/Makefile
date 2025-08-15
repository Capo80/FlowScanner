CC_64=gcc

CFLAGS=-m64 -Wall -Wextra -s -O2 -Os
#CFLAGS=-m64 -Wall -Wextra

# -s: remove all symbol table and relocation information
# -O2: optimization
# -Os: size optimization

self-inject: self-inject.c crypt.c shellcode_enc.h
	$(CC_64) $(CFLAGS) self-inject.c crypt.c -o self-inject -pthread

encrypt: encrypt.c crypt.c shellcode.h
	$(CC_64) $(CFLAGS) encrypt.c crypt.c -o encrypt

clean:
	rm -rf self-inject
	rm -rf encrypt