INCLUDES = [
    '#include "openssl/ssl.h"',
]

SETUP = [
    'OpenSSL_add_all_digests',
    'OpenSSL_add_all_ciphers',
]

TYPES = [
    "static const int OPENSSL_VERSION_NUMBER;",
]

FUNCTIONS = [
    "void OpenSSL_add_all_algorithms(void);",
    "void OpenSSL_add_all_ciphers(void);",
    "void OpenSSL_add_all_digests(void);",
]
