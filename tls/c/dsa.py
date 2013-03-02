INCLUDES = [
    '#include <openssl/dsa.h>',
    ]

TYPES = [
    'typedef ... DSA;',
    ]

FUNCTIONS = [
    """
    DSA *      DSA_generate_parameters(int bits,
                                       unsigned char *seed,int seed_len,
                                       int *counter_ret, unsigned long *h_ret,void
                                       (*callback)(int, int, void *),void *cb_arg);
    """,
    "int   DSA_generate_key(DSA *a);",
    "void DSA_free(DSA *dsa);",
    ]
