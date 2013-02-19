INCLUDES = [
    '#include "openssl/evp.h"',
]

TEARDOWN = [
    'EVP_cleanup',
]

TYPES = [
    'static const int EVP_PKEY_RSA;',
    'static const int EVP_PKEY_DSA;',

    'typedef ... ENGINE;',
    'typedef ... EVP_MD;',

    """
    typedef struct evp_pkey_st {
        int type;
        ...;
    } EVP_PKEY;
    """,
]

FUNCTIONS = [
    'EVP_PKEY *EVP_PKEY_new(void);',
    'void EVP_PKEY_free(EVP_PKEY *key);',

    'int EVP_PKEY_type(int type);',
    'RSA *EVP_PKEY_get1_RSA(EVP_PKEY *pkey);',

    'int EVP_PKEY_assign_RSA(EVP_PKEY *pkey,RSA *key);',
    'int EVP_PKEY_assign_DSA(EVP_PKEY *pkey,DSA *key);',

    'const EVP_MD *EVP_get_digestbyname(const char *name);',
]
