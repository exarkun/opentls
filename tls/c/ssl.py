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
    'typedef ... SSL;',
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

    # SSL
    'int SSL_get_verify_mode(const SSL *ssl);',
    'void SSL_set_verify_depth(SSL *s, int depth);',
    'int SSL_get_verify_depth(const SSL *ssl);',
    'int (*SSL_get_verify_callback(const SSL *ssl))(int, X509_STORE_CTX *);',
    'long SSL_set_mode(SSL *ssl, long mode);',
    'long SSL_get_mode(SSL *ssl);',

    # context
    'SSL_CTX *SSL_CTX_new(SSL_METHOD *method);',
    'void SSL_CTX_free(SSL_CTX *ctx);',

    'long SSL_CTX_set_timeout(SSL_CTX *ctx, long t);',
    'long SSL_CTX_get_timeout(SSL_CTX *ctx);',

    """
    void SSL_CTX_set_verify(SSL_CTX *ctx, int mode,
                            int (*verify_callback)(int, X509_STORE_CTX *));
    """,
    'void SSL_CTX_set_verify_depth(SSL_CTX *ctx,int depth);',

    'int (*SSL_CTX_get_verify_callback(const SSL_CTX *ctx))(int, X509_STORE_CTX *);',

    'long SSL_CTX_set_mode(SSL_CTX *ctx, long mode);',
    'long SSL_CTX_get_mode(SSL_CTX *ctx);',

    'long SSL_CTX_set_session_cache_mode(SSL_CTX *ctx, long mode);',
    'long SSL_CTX_get_session_cache_mode(SSL_CTX *ctx);',

    'int SSL_CTX_get_verify_mode(const SSL_CTX *ctx);',
    'int SSL_CTX_get_verify_depth(const SSL_CTX *ctx);',

    """
    int SSL_CTX_load_verify_locations(SSL_CTX *ctx, const char *CAfile,
                                      const char *CApath);
    """,
    "long SSL_CTX_set_tmp_dh(SSL_CTX *ctx, DH *dh);",

    "long SSL_CTX_add_extra_chain_cert(SSL_CTX *ctx, X509 *x509);",

    "void SSL_CTX_set_default_passwd_cb(SSL_CTX *ctx, pem_password_cb *cb);",
    "void SSL_CTX_set_default_passwd_cb_userdata(SSL_CTX *ctx, void *u);",

    "int SSL_CTX_use_PrivateKey(SSL_CTX *ctx, EVP_PKEY *pkey);",
    "int SSL_CTX_use_PrivateKey_file(SSL_CTX *ctx, const char *file, int type);",
]
