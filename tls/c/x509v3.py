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

    "typedef void * (*X509V3_EXT_D2I)(void *, const unsigned char ** , long);",

    """
    typedef struct {
        ASN1_ITEM_EXP *it;
        X509V3_EXT_D2I d2i;
        ...;
    } X509V3_EXT_METHOD;
    """,

    "static const int GEN_OTHERNAME;",
    "static const int GEN_EMAIL;",
    "static const int GEN_X400;",
    "static const int GEN_DNS;",
    "static const int GEN_URI;",
    "static const int GEN_DIRNAME;",
    "static const int GEN_EDIPARTY;",
    "static const int GEN_IPADD;",
    "static const int GEN_RID;",

    """
    typedef struct {
        ...;
    } OTHERNAME;
    """,

    """
    typedef struct {
        ...;
    } EDIPARTYNAME;
    """,

    """
    typedef struct {
        int type;
        union {
            char *ptr;
            OTHERNAME *otherName; /* otherName */
            ASN1_IA5STRING *rfc822Name;
            ASN1_IA5STRING *dNSName;
            ASN1_TYPE *x400Address;
            X509_NAME *directoryName;
            EDIPARTYNAME *ediPartyName;
            ASN1_IA5STRING *uniformResourceIdentifier;
            ASN1_OCTET_STRING *iPAddress;
            ASN1_OBJECT *registeredID;

            /* Old names */
            ASN1_OCTET_STRING *ip; /* iPAddress */
            X509_NAME *dirn;                /* dirn */
            ASN1_IA5STRING *ia5;/* rfc822Name, dNSName, uniformResourceIdentifier */
            ASN1_OBJECT *rid; /* registeredID */
            ASN1_TYPE *other; /* x400Address */
        } d;
        ...;
    } GENERAL_NAME;
    """,

    "typedef struct stack_st_GENERAL_NAME GENERAL_NAMES;",
]

FUNCTIONS = [
    'void X509V3_set_ctx(X509V3_CTX *ctx, X509 *issuer, X509 *subject,X509_REQ *req, X509_CRL *crl, int flags);',
    'void* X509V3_set_ctx_nodb(X509V3_CTX *ctx);',
    'X509_EXTENSION *X509V3_EXT_nconf(CONF *conf, X509V3_CTX *ctx, char *name, char *value);',

    'const X509V3_EXT_METHOD *X509V3_EXT_get(X509_EXTENSION *ext);',
    'const X509V3_EXT_METHOD *X509V3_EXT_get_nid(int nid);',

    'int sk_GENERAL_NAME_num(struct stack_st_GENERAL_NAME * stack);',
    'int sk_GENERAL_NAME_push(struct stack_st_GENERAL_NAME * stack, GENERAL_NAME * name);',
    'GENERAL_NAME * sk_GENERAL_NAME_value(struct stack_st_GENERAL_NAME * stack, int index);',
    'int GENERAL_NAME_print(BIO *out, GENERAL_NAME *gen);',

]
