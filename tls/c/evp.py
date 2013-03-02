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
    'int           EVP_PKEY_bits(EVP_PKEY *pkey);',
    'RSA *EVP_PKEY_get1_RSA(EVP_PKEY *pkey);',

    'int  EVP_SignInit(EVP_MD_CTX *ctx, const EVP_MD *type);',
    'int  EVP_SignUpdate(EVP_MD_CTX *ctx,const void *d, size_t cnt);',
    'int  EVP_SignFinal(EVP_MD_CTX *ctx,unsigned char *md,unsigned int *s, EVP_PKEY *pkey);',

    'int  EVP_VerifyInit(EVP_MD_CTX *ctx, const EVP_MD *type);',
    'int  EVP_VerifyUpdate(EVP_MD_CTX *ctx,const void *d, size_t cnt);',
    'int  EVP_VerifyFinal(EVP_MD_CTX *ctx,unsigned char *md,unsigned int s, EVP_PKEY *pkey);',

    'int EVP_MD_CTX_cleanup(EVP_MD_CTX *ctx);',
    'void EVP_MD_CTX_destroy(EVP_MD_CTX *ctx);',

    'int EVP_PKEY_assign_RSA(EVP_PKEY *pkey,RSA *key);',
    'int EVP_PKEY_assign_DSA(EVP_PKEY *pkey,DSA *key);',

    'const EVP_MD *EVP_get_digestbyname(const char *name);',
]
