INCLUDES = [
    "#include <openssl/x509v3.h>",
]

TYPES = [
    """
    typedef struct {
        X509 *issuer_cert;
        X509 *subject_cert;
        ...;
    } X509V3_CTX;
    """,
]

FUNCTIONS = [
    'void X509V3_set_ctx(X509V3_CTX *ctx, X509 *issuer, X509 *subject,X509_REQ *req, X509_CRL *crl, int flags);',
    'void* X509V3_set_ctx_nodb(X509V3_CTX *ctx);',
    'X509_EXTENSION *X509V3_EXT_nconf(CONF *conf, X509V3_CTX *ctx, char *name, char *value);',
]
