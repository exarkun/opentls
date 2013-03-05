INCLUDES = [
    "#include <openssl/dh.h>",
]

TYPES = [
    "typedef ... DH;",
]

FUNCTIONS = [
    "DH* DH_new(void);",
    "void DH_free(DH *dh);",
]

