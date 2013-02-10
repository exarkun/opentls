INCLUDES = [
    '#include "openssl/evp.h"',
]

TEARDOWN = [
    'EVP_cleanup',
]

TYPES = [
    'static const int EVP_PKEY_RSA;',
    'typedef ... ENGINE;',

    """
    typedef struct evp_pkey_st {
        int type;
        ...;
    } EVP_PKEY;
    """,

]

FUNCTIONS = [
    'int EVP_PKEY_type(int type);',
    'RSA *EVP_PKEY_get1_RSA(EVP_PKEY *pkey);',
]
