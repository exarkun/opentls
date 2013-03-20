INCLUDES = [
    '#include <openssl/crypto.h>',
]

TYPES = [
]

FUNCTIONS = [
    "void CRYPTO_add(int *references, int count, int type);",
    "void CRYPTO_free(void *);",
]
