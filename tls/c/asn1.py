INCLUDES = [
    '#include <openssl/asn1.h>',
]

TYPES = [
    'typedef ... ASN1_INTEGER;',
    'typedef ... ASN1_OCTET_STRING;',
    'typedef ... ASN1_OBJECT;',
    'typedef ... ASN1_STRING;',
    'typedef ... ASN1_TYPE;',
    'typedef ... ASN1_GENERALIZEDTIME;',

    """
    typedef struct {
        ...;
    } ASN1_TIME;
    """,

    'typedef ... ASN1_UTCTIME;',

    'static const int V_ASN1_GENERALIZEDTIME;',

    'static const int MBSTRING_UTF8;',
]

FUNCTIONS = [
    'ASN1_OBJECT *ASN1_OBJECT_new(void);',
    'void ASN1_OBJECT_free(ASN1_OBJECT *a);',
    # ASN1 OBJECT IDENTIFIER
    'ASN1_OBJECT *d2i_ASN1_OBJECT(ASN1_OBJECT **a, const unsigned char **pp, long length);',
    'int i2d_ASN1_OBJECT(ASN1_OBJECT *a, unsigned char **pp);',
    # ASN1 STRING
    'ASN1_STRING * ASN1_STRING_new(void);',
    'ASN1_STRING * ASN1_STRING_type_new(int type);',
    'void ASN1_STRING_free(ASN1_STRING *a);',
    'int ASN1_STRING_length(ASN1_STRING *x);',
    'unsigned char * ASN1_STRING_data(ASN1_STRING *x);',
    'ASN1_STRING * ASN1_STRING_dup(ASN1_STRING *a);',
    'int ASN1_STRING_cmp(ASN1_STRING *a, ASN1_STRING *b);',
    'int ASN1_STRING_set(ASN1_STRING *str, const void *data, int len);',
    'int ASN1_STRING_type(ASN1_STRING *x);',
    'int ASN1_STRING_to_UTF8(unsigned char **out, ASN1_STRING *in);',
    # ASN1 OCTET STRING
    'ASN1_OCTET_STRING * ASN1_OCTET_STRING_new(void);',
    'void ASN1_OCTET_STRING_free(ASN1_OCTET_STRING *a);',
    'ASN1_OCTET_STRING * ASN1_OCTET_STRING_dup(ASN1_OCTET_STRING *a);',
    'int ASN1_OCTET_STRING_cmp(ASN1_OCTET_STRING *a, ASN1_OCTET_STRING *b);',
    'int ASN1_OCTET_STRING_set(ASN1_OCTET_STRING *str, const void *data, int len);',
    # ASN1 INTEGER
    'ASN1_INTEGER * ASN1_INTEGER_new(void);',
    'void ASN1_INTEGER_free(ASN1_INTEGER *a);',
    'ASN1_INTEGER * ASN1_INTEGER_dup(ASN1_INTEGER *a);',
    'int ASN1_INTEGER_cmp(ASN1_INTEGER *a, ASN1_INTEGER *b);',
    'int ASN1_INTEGER_set(ASN1_INTEGER *a, long v);',
    'long ASN1_INTEGER_get(ASN1_INTEGER *a);',
    'BIGNUM *ASN1_INTEGER_to_BN(const ASN1_INTEGER *ai,BIGNUM *bn);',

    # ASN1 TIME
    'ASN1_GENERALIZEDTIME *ASN1_TIME_to_generalizedtime(ASN1_TIME *t, ASN1_GENERALIZEDTIME **out);',

    # ASN1 UTCTIME
    'int ASN1_UTCTIME_cmp_time_t(const ASN1_UTCTIME *s, time_t t);',

    # ASN1 GENERALIZEDTIME
    'int ASN1_GENERALIZEDTIME_set_string(ASN1_GENERALIZEDTIME *s, const char *str);',
    'void ASN1_GENERALIZEDTIME_free(ASN1_GENERALIZEDTIME *s);',
    'int ASN1_GENERALIZEDTIME_check(ASN1_GENERALIZEDTIME *a);',
]
