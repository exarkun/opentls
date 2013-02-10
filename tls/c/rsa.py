INCLUDES = [
    '#include <openssl/rsa.h>',
    ]

TYPES = [
    'typedef ... RSA;',
    ]

FUNCTIONS = [
    'int RSA_check_key(RSA *rsa);',
    'int  RSA_print(BIO *bp, const RSA *r,int offset);',
    ]
