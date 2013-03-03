INCLUDES = [
    "#include <openssl/pkcs7.h>",
]

TYPES = [
    """
    typedef struct {
        ASN1_OBJECT *type;
        ...;
    } PKCS7;
    """,
]

FUNCTIONS = [
    "void PKCS7_free(PKCS7* pkcs7);",
    "int PKCS7_type_is_signed(PKCS7* pkcs7);",
    "int PKCS7_type_is_enveloped(PKCS7* pkcs7);",
    "int PKCS7_type_is_signedAndEnveloped(PKCS7* pkcs7);",
    "int PKCS7_type_is_data(PKCS7* pkcs7);",
]
