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

    """
    typedef struct {
        ASN1_OBJECT *object;
        ASN1_BOOLEAN critical;
        ASN1_OCTET_STRING *value;
    } X509_EXTENSION;
    """,

    'typedef ... X509_EXTENSIONS;',

    'typedef ... X509_REQ;',

    'typedef ... x509_revoked_st;',

    """
    typedef struct {
        ASN1_INTEGER *serialNumber;
        ASN1_TIME *revocationDate;
        X509_EXTENSIONS *extensions;
        int sequence;
        ...;
    } X509_REVOKED;
    """,

    """
    typedef struct {
        struct x509_revoked_st *revoked;
        ...;
    } X509_CRL_INFO;
    """,

    """
    typedef struct {
        X509_CRL_INFO *crl;
        ...;
    } X509_CRL;
    """,

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
    'int X509_REQ_add_extensions(X509_REQ *req, X509_EXTENSIONS *exts);',
    'int         X509_REQ_print_ex(BIO *bp, X509_REQ *x, unsigned long nmflag, unsigned long cflag);',

    'X509_EXTENSIONS * sk_X509_EXTENSION_new_null();',
    'int sk_X509_EXTENSION_num(X509_EXTENSIONS * stack);',
    'X509_EXTENSION * sk_X509_EXTENSION_value(X509_EXTENSIONS * stack, int index);',
    'void sk_X509_EXTENSION_push(X509_EXTENSIONS * stack, X509_EXTENSION * ext);',

    'int X509V3_EXT_print(BIO *out, X509_EXTENSION *ext, unsigned long flag, int indent);',
    'ASN1_OCTET_STRING *X509_EXTENSION_get_data(X509_EXTENSION *ne);',

    'X509_REVOKED *X509_REVOKED_new();',
    'int sk_X509_REVOKED_num(struct x509_revoked_st *revoked);',
    'X509_REVOKED * sk_X509_REVOKED_value(struct x509_revoked_st *revoked, int index);',
    'int X509_REVOKED_set_serialNumber(X509_REVOKED *x, ASN1_INTEGER *serial);',

    """
    int         X509_REVOKED_add1_ext_i2d(X509_REVOKED *x, int nid, void *value, int crit,
                                          unsigned long flags);
    """,

    'X509_CRL *d2i_X509_CRL_bio(BIO *bp,X509_CRL **crl);',
    'X509_CRL *X509_CRL_new();',
    'int X509_CRL_add0_revoked(X509_CRL *crl, X509_REVOKED *rev);',


    # ASN1 serialization
    'int i2d_X509_bio(BIO *bp, X509 *x);',
    'X509 *d2i_X509_bio(BIO *bp, X509 **x);',

    'int i2d_X509_REQ_bio(BIO *bp,X509_REQ *req);',
    'X509_REQ *d2i_X509_REQ_bio(BIO *bp,X509_REQ **req);',

    'int i2d_PrivateKey_bio(BIO *bp, EVP_PKEY *pkey);',
    'EVP_PKEY *d2i_PrivateKey_bio(BIO *bp, EVP_PKEY **a);',

    'ASN1_INTEGER *      X509_get_serialNumber(X509 *x);',
    'int                 X509_set_serialNumber(X509 *x, ASN1_INTEGER *serial);',
]
