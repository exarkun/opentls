INCLUDES = [
    '#include <openssl/rsa.h>',
    ]

TYPES = [
    'typedef ... RSA;',
    'static const int RSA_F4;',
    ]

FUNCTIONS = [
    'RSA *   RSA_new(void);',
    'void RSA_free(RSA *rsa);',

    'int     RSA_generate_key_ex(RSA *rsa, int bits, BIGNUM *e, BN_GENCB *cb);',

    'int RSA_check_key(RSA *rsa);',
    'int  RSA_print(BIO *bp, const RSA *r,int offset);',
    ]
