INCLUDES = [
    '#include <openssl/bn.h>',
]

TYPES = [
    'typedef ... BIGNUM;',
    'typedef ... BN_GENCB;',
]

FUNCTIONS = [
    'BIGNUM *BN_new(void);',
    'void  BN_free(BIGNUM *a);',

    'char *        BN_bn2hex(const BIGNUM *a);',
    'int   BN_hex2bn(BIGNUM **a, const char *str);',
    'int BN_set_word(BIGNUM *a, unsigned long w);',

    'ASN1_INTEGER *BN_to_ASN1_INTEGER(const BIGNUM *bn, ASN1_INTEGER *ai);',
]

