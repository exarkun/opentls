INCLUDES = [
    '#include <openssl/ssl.h>',
]

SETUP = [
    'SSL_library_init',
]

TYPES = [
    'static const int SSL_FILETYPE_PEM;',
    'static const int SSL_FILETYPE_ASN1;',

    'static const int SSL_ERROR_NONE;',
    'static const int SSL_ERROR_ZERO_RETURN;',
    'static const int SSL_ERROR_WANT_READ;',
    'static const int SSL_ERROR_WANT_WRITE;',
    'static const int SSL_ERROR_WANT_X509_LOOKUP;',
    'static const int SSL_ERROR_SYSCALL;',
    'static const int SSL_ERROR_SSL;',

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

    'typedef ... X509_STORE_CTX;',
    'static const int X509_V_OK;',

    'typedef ... SSL_METHOD;',
    'typedef ... SSL_CTX;',
    'typedef ... SSL;',

    'typedef int verify_callback(int preverify_ok, X509_STORE_CTX *x509_ctx);',
    'typedef void info_callback(SSL *ssl, int where, int ret);',
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

    'void SSL_set_info_callback(SSL *ssl, void (*callback)());',
    'void (*SSL_get_info_callback(const SSL *ssl))();',

    'SSL *SSL_new(SSL_CTX *ctx);',
    'int SSL_set_fd(SSL *ssl, int fd);',
    'void SSL_set_bio(SSL *ssl, BIO *rbio, BIO *wbio);',

    'void SSL_set_connect_state(SSL *ssl);',
    'void SSL_set_accept_state(SSL *ssl);',

    'int SSL_write(SSL *ssl, const void *buf, int num);',
    'int SSL_read(SSL *ssl, void *buf, int num);',
    'X509 *SSL_get_peer_certificate(const SSL *ssl);',

    'int SSL_get_error(const SSL *ssl, int ret);',
    'int SSL_do_handshake(SSL *ssl);',
    'int SSL_shutdown(SSL *ssl);',
    'void SSL_set_shutdown(SSL *ssl, int mode);',
    'int SSL_get_shutdown(const SSL *ssl);',

    'struct stack_st_SSL_CIPHER *SSL_get_ciphers(const SSL *ssl);',
    'const char *SSL_get_cipher_list(const SSL *ssl, int priority);',

    # context
    'SSL_CTX *SSL_CTX_new(SSL_METHOD *method);',
    'void SSL_CTX_free(SSL_CTX *ctx);',

    'long SSL_CTX_set_timeout(SSL_CTX *ctx, long t);',
    'long SSL_CTX_get_timeout(SSL_CTX *ctx);',

    'int SSL_CTX_set_default_verify_paths(SSL_CTX *ctx);',
    'void SSL_CTX_set_verify(SSL_CTX *ctx, int mode, verify_callback cb);',
    'void SSL_CTX_set_verify_depth(SSL_CTX *ctx,int depth);',

    'int (*SSL_CTX_get_verify_callback(const SSL_CTX *ctx))(int, X509_STORE_CTX *);',

    'void SSL_CTX_set_info_callback(SSL_CTX *ctx, info_callback cb);',
    'void (*SSL_CTX_get_info_callback(const SSL_CTX *ctx))();',

    'long SSL_CTX_set_mode(SSL_CTX *ctx, long mode);',
    'long SSL_CTX_get_mode(SSL_CTX *ctx);',

    'long SSL_CTX_set_session_cache_mode(SSL_CTX *ctx, long mode);',
    'long SSL_CTX_get_session_cache_mode(SSL_CTX *ctx);',

    'int SSL_CTX_get_verify_mode(const SSL_CTX *ctx);',
    'int SSL_CTX_get_verify_depth(const SSL_CTX *ctx);',

    'int SSL_CTX_set_cipher_list(SSL_CTX *ctx, const char *str);',

    """
    int SSL_CTX_load_verify_locations(SSL_CTX *ctx, const char *CAfile,
                                      const char *CApath);
    """,
    "long SSL_CTX_set_tmp_dh(SSL_CTX *ctx, DH *dh);",

    "long SSL_CTX_add_extra_chain_cert(SSL_CTX *ctx, X509 *x509);",

    "void SSL_CTX_set_default_passwd_cb(SSL_CTX *ctx, pem_password_cb *cb);",
    "void SSL_CTX_set_default_passwd_cb_userdata(SSL_CTX *ctx, void *u);",

    "int SSL_CTX_use_certificate(SSL_CTX *ctx, X509 *x);",
    "int SSL_CTX_use_certificate_chain_file(SSL_CTX *ctx, const char *file);",

    "int SSL_CTX_use_PrivateKey(SSL_CTX *ctx, EVP_PKEY *pkey);",
    "int SSL_CTX_use_PrivateKey_file(SSL_CTX *ctx, const char *file, int type);",

    # X509_STORE_CTX
    "int    X509_STORE_CTX_get_error(X509_STORE_CTX *ctx);",
    "void   X509_STORE_CTX_set_error(X509_STORE_CTX *ctx,int s);",
    "int    X509_STORE_CTX_get_error_depth(X509_STORE_CTX *ctx);",
    "X509 * X509_STORE_CTX_get_current_cert(X509_STORE_CTX *ctx);",

]
