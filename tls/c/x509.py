INCLUDES = [
    '#include <openssl/ssl.h>',
]

TYPES = [
    'typedef int time_t;',

    """
    typedef struct {
        ASN1_OBJECT *algorithm;
        ...;
    } X509_ALGOR;
    """,

    """
    typedef struct {
        X509_ALGOR *signature;
        ...;
    } X509_CINF;
    """,

    'typedef ... X509_EXTENSION;',

    'typedef ... X509_REQ;',
    'typedef ... X509_CRL;',

    """
    typedef struct {
        X509_CINF *cert_info;
        ...;
    } X509;
    """,
]

FUNCTIONS = [
    'X509 *X509_new(void);',
    'void X509_free(X509 *a);',

    'int X509_print_ex(BIO *bp,X509 *x, unsigned long nmflag, unsigned long cflag);',

    'int X509_set_version(X509 *x,long version);',
    'long X509_get_version(X509 *x);',

    'EVP_PKEY *  X509_get_pubkey(X509 *x);',
    'int                 X509_set_pubkey(X509 *x, EVP_PKEY *pkey);',

    'int X509_sign(X509 *x, EVP_PKEY *pkey, const EVP_MD *md);',

    'int X509_digest(const X509 *data,const EVP_MD *type, unsigned char *md, unsigned int *len);',

    'ASN1_TIME *X509_gmtime_adj(ASN1_TIME *s, long adj);',
    'ASN1_TIME *X509_get_notBefore(X509 *x);',
    'ASN1_TIME *X509_get_notAfter(X509 *x);',

    'unsigned long X509_subject_name_hash(X509 *a);',

    'X509_NAME * X509_get_subject_name(X509 *a);',
    'int                 X509_set_subject_name(X509 *x, X509_NAME *name);',

    'X509_NAME * X509_get_issuer_name(X509 *a);',
    'int                 X509_set_issuer_name(X509 *x, X509_NAME *name);',

    'int          X509_get_ext_count(X509 *x);',
    'int          X509_add_ext(X509 *x, X509_EXTENSION *ex, int loc);',
    'X509_EXTENSION *X509_EXTENSION_dup(X509_EXTENSION *ex);',
    'X509_EXTENSION *X509_get_ext(X509 *x, int loc);',
    'int         X509_EXTENSION_get_critical(X509_EXTENSION *ex);',
    'ASN1_OBJECT *       X509_EXTENSION_get_object(X509_EXTENSION *ex);',

    'int          X509_REQ_set_version(X509_REQ *x,long version);',
    'long          X509_REQ_get_version(X509_REQ *x);',
    'X509_REQ *  X509_REQ_new();',
    'int              X509_REQ_set_pubkey(X509_REQ *x, EVP_PKEY *pkey);',
    'int X509_REQ_sign(X509_REQ *x, EVP_PKEY *pkey, const EVP_MD *md);',
    'EVP_PKEY *       X509_REQ_get_pubkey(X509_REQ *req);',
    'X509_NAME *    X509_REQ_get_subject_name(X509_REQ *req);',

    # ASN1 serialization
    'int i2d_X509_bio(BIO *bp, X509 *x);',
    'X509 *d2i_X509_bio(BIO *bp, X509 **x);',

    'int i2d_PrivateKey_bio(BIO *bp, EVP_PKEY *pkey);',
    'EVP_PKEY *d2i_PrivateKey_bio(BIO *bp, EVP_PKEY **a);',

    'ASN1_INTEGER *      X509_get_serialNumber(X509 *x);',
    'int                 X509_set_serialNumber(X509 *x, ASN1_INTEGER *serial);',
]
