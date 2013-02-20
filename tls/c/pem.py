INCLUDES = [
    '#include <openssl/pem.h>',
]

TYPES = [
    'typedef ... EVP_CIPHER;',
    'typedef int pem_password_cb(char *buf, int size, int rwflag, void *userdata);',
]

FUNCTIONS = [
    'X509 *PEM_read_bio_X509(BIO *bp, X509 **x, pem_password_cb *cb, void *u);',
    'int PEM_write_bio_X509(BIO *bp, X509 *x);',

    """
    int PEM_write_bio_PrivateKey(BIO *bp, EVP_PKEY *x, const EVP_CIPHER *enc,
                                 unsigned char *kstr, int klen,
                                 pem_password_cb *cb, void *u);
    """,

    """
    EVP_PKEY *PEM_read_bio_PrivateKey(BIO *bp, EVP_PKEY **x,
                                      pem_password_cb *cb, void *u);
    """,

]
