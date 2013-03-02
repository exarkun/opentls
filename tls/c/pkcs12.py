INCLUDES = [
    "#include <openssl/pkcs12.h>",
]

TYPES = [
    "typedef ... PKCS12;",
]

FUNCTIONS = [
    """
    int PKCS12_parse(PKCS12 *p12, const char *pass, EVP_PKEY **pkey, X509 **cert,
                     struct stack_st_X509 **ca);
    """,

    """
    PKCS12 *PKCS12_create(char *pass, char *name, EVP_PKEY *pkey, X509 *cert,
                          struct stack_st_X509 *ca, int nid_key, int nid_cert, int iter,
                          int mac_iter, int keytype);
    """,

    "PKCS12 *d2i_PKCS12_bio(BIO *bp, PKCS12 **p12);",
    "int i2d_PKCS12_bio(BIO *bp, PKCS12 *p12);",
]
