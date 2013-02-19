INCLUDES = [
    '#include <openssl/ssl.h>',
]

TYPES = [
    'typedef int time_t;',
    'typedef ... ASN1_TIME;',
    'typedef ... ASN1_UTCTIME;',
    'typedef ... X509;',
]

FUNCTIONS = [
    'X509 *X509_new(void);',
    'void X509_free(X509 *a);',

    'int X509_print_ex(BIO *bp,X509 *x, unsigned long nmflag, unsigned long cflag);',

    'int X509_set_version(X509 *x,long version);',
    'long X509_get_version(X509 *x);',

    'int                 X509_set_pubkey(X509 *x, EVP_PKEY *pkey);',

    'int X509_sign(X509 *x, EVP_PKEY *pkey, const EVP_MD *md);',

    'ASN1_UTCTIME *X509_gmtime_adj(ASN1_UTCTIME *s, long adj);',
    'ASN1_UTCTIME *X509_get_notBefore(X509 *x);',
    'ASN1_UTCTIME *X509_get_notAfter(X509 *x);',

    # ASN1 serialization
    'int i2d_X509_bio(BIO *bp, X509 *x);',
    'X509 *d2i_X509_bio(BIO *bp, X509 **x);',

    'int i2d_PrivateKey_bio(BIO *bp, EVP_PKEY *pkey);',
    'EVP_PKEY *d2i_PrivateKey_bio(BIO *bp, EVP_PKEY **a);',

    'unsigned long X509_subject_name_hash(X509 *a);',
    'ASN1_INTEGER *      X509_get_serialNumber(X509 *x);',
    'int                 X509_set_serialNumber(X509 *x, ASN1_INTEGER *serial);',
]
