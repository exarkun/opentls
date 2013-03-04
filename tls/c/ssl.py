INCLUDES = [
    '#include <openssl/ssl.h>',
]

SETUP = [
    'SSL_library_init',
]

TYPES = [
    'static const int SSL_FILETYPE_PEM;',
    'static const int SSL_FILETYPE_ASN1;',

    'static const int SSL_SENT_SHUTDOWN;',
    'static const int SSL_RECEIVED_SHUTDOWN;',

    'static const int SSL_OP_NO_SSLv2;',
    'static const int SSL_OP_NO_SSLv3;',

    'static const int SSL_OP_SINGLE_DH_USE;',

    'static const int SSL_VERIFY_PEER;',
    'static const int SSL_VERIFY_FAIL_IF_NO_PEER_CERT;',
    'static const int SSL_VERIFY_CLIENT_ONCE;',
    'static const int SSL_VERIFY_NONE;',

    'static const int SSL_SESS_CACHE_OFF;',
    'static const int SSL_SESS_CACHE_CLIENT;',
    'static const int SSL_SESS_CACHE_SERVER;',
    'static const int SSL_SESS_CACHE_BOTH;',
    'static const int SSL_SESS_CACHE_NO_AUTO_CLEAR;',
    'static const int SSL_SESS_CACHE_NO_INTERNAL_LOOKUP;',
    'static const int SSL_SESS_CACHE_NO_INTERNAL_STORE;',
    'static const int SSL_SESS_CACHE_NO_INTERNAL;',

    'typedef ... SSL_METHOD;',
    'typedef ... SSL_CTX;',
]

FUNCTIONS = [
    'void *OPENSSL_malloc(int num);',
    'void OPENSSL_free(void *);',

    'int SSL_library_init(void);',
    # methods
#   'SSL_METHOD *SSLv2_method(void);',
#   'SSL_METHOD *SSLv2_server_method(void);',
#   'SSL_METHOD *SSLv2_client_method(void);',
    'const SSL_METHOD *SSLv3_method(void);',
    'const SSL_METHOD *SSLv3_server_method(void);',
    'const SSL_METHOD *SSLv3_client_method(void);',
    'const SSL_METHOD *TLSv1_method(void);',
    'const SSL_METHOD *TLSv1_server_method(void);',
    'const SSL_METHOD *TLSv1_client_method(void);',
    'const SSL_METHOD *SSLv23_method(void);',
    'const SSL_METHOD *SSLv23_server_method(void);',
    'const SSL_METHOD *SSLv23_client_method(void);',
    # context
    'SSL_CTX *SSL_CTX_new(SSL_METHOD *method);',
    'void SSL_CTX_free(SSL_CTX *ctx);',
]
