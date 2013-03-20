INCLUDES = [
    '#include <openssl/ssl.h>',
]

SETUP = [
    'SSL_library_init',
]

TYPES = [
    # Internally invented symbol to tell us if SSLv2 is supported
    'static const int PYOPENSSL_NO_SSL2;',
    # Internally invented symbol to tell us if SNI is supported
    'static const int PYOPENSSL_TLSEXT_HOSTNAME;',

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
    'static const int SSL_OP_NO_TLSv1;',

    'static const int SSL_OP_SINGLE_DH_USE;',
    'static const int SSL_OP_EPHEMERAL_RSA;',
    'static const int SSL_OP_MICROSOFT_SESS_ID_BUG;',
    'static const int SSL_OP_NETSCAPE_CHALLENGE_BUG;',
    'static const int SSL_OP_NETSCAPE_REUSE_CIPHER_CHANGE_BUG;',
    'static const int SSL_OP_SSLREF2_REUSE_CERT_TYPE_BUG;',
    'static const int SSL_OP_MICROSOFT_BIG_SSLV3_BUFFER;',
    'static const int SSL_OP_MSIE_SSLV2_RSA_PADDING;',
    'static const int SSL_OP_SSLEAY_080_CLIENT_DH_BUG;',
    'static const int SSL_OP_TLS_D5_BUG;',
    'static const int SSL_OP_TLS_BLOCK_PADDING_BUG;',
    'static const int SSL_OP_DONT_INSERT_EMPTY_FRAGMENTS;',
    'static const int SSL_OP_CIPHER_SERVER_PREFERENCE;',
    'static const int SSL_OP_TLS_ROLLBACK_BUG;',
    'static const int SSL_OP_PKCS1_CHECK_1;',
    'static const int SSL_OP_PKCS1_CHECK_2;',
    'static const int SSL_OP_NETSCAPE_CA_DN_BUG;',
    'static const int SSL_OP_NETSCAPE_DEMO_CIPHER_CHANGE_BUG;',
    'static const int SSL_OP_NO_COMPRESSION;',

    'static const int SSL_OP_NO_QUERY_MTU;',
    'static const int SSL_OP_COOKIE_EXCHANGE;',
    'static const int SSL_OP_NO_TICKET;',

    'static const int SSL_OP_ALL;',

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

    'static const int SSL_ST_CONNECT;',
    'static const int SSL_ST_ACCEPT;',
    'static const int SSL_ST_MASK;',
    'static const int SSL_ST_INIT;',
    'static const int SSL_ST_BEFORE;',
    'static const int SSL_ST_OK;',
    'static const int SSL_ST_RENEGOTIATE;',

    'static const int SSL_CB_LOOP;',
    'static const int SSL_CB_EXIT;',
    'static const int SSL_CB_READ;',
    'static const int SSL_CB_WRITE;',
    'static const int SSL_CB_ALERT;',
    'static const int SSL_CB_READ_ALERT;',
    'static const int SSL_CB_WRITE_ALERT;',
    'static const int SSL_CB_ACCEPT_LOOP;',
    'static const int SSL_CB_ACCEPT_EXIT;',
    'static const int SSL_CB_CONNECT_LOOP;',
    'static const int SSL_CB_CONNECT_EXIT;',
    'static const int SSL_CB_HANDSHAKE_START;',
    'static const int SSL_CB_HANDSHAKE_DONE;',

    'static const int SSL_MODE_RELEASE_BUFFERS;',
    'static const int SSL_MODE_ENABLE_PARTIAL_WRITE;',
    'static const int SSL_MODE_ACCEPT_MOVING_WRITE_BUFFER;',
    'static const int SSL_MODE_AUTO_RETRY;',

    'static const int SSL3_RANDOM_SIZE;',

    'typedef ... X509_STORE_CTX;',
    'static const int X509_V_OK;',

    'typedef ... SSL_METHOD;',
    'typedef ... SSL_CTX;',

    """
    typedef struct {
	int master_key_length;
	unsigned char master_key[...];
        ...;
    } SSL_SESSION;
    """,

    """
    typedef struct {
	unsigned char server_random[...];
	unsigned char client_random[...];
        ...;
    } SSL3_STATE;
    """,

    """
    typedef struct {
        SSL3_STATE *s3;
        SSL_SESSION *session;
        ...;
    } SSL;
    """

    'static const int TLSEXT_NAMETYPE_host_name;',

    'typedef int verify_callback(int preverify_ok, X509_STORE_CTX *x509_ctx);',
    'typedef void info_callback(const SSL *ssl, int where, int ret);',
    'typedef int tlsext_servername_callback(const SSL *ssl, int *alert, void *arg);',
]

FUNCTIONS = [
    'void *OPENSSL_malloc(int num);',
    'void OPENSSL_free(void *);',

    'int SSL_library_init(void);',
    # methods

    'const SSL_METHOD *SSLv3_method(void);',
    'const SSL_METHOD *SSLv3_server_method(void);',
    'const SSL_METHOD *SSLv3_client_method(void);',
    'const SSL_METHOD *TLSv1_method(void);',
    'const SSL_METHOD *TLSv1_server_method(void);',
    'const SSL_METHOD *TLSv1_client_method(void);',
    'const SSL_METHOD *SSLv23_method(void);',
    'const SSL_METHOD *SSLv23_server_method(void);',
    'const SSL_METHOD *SSLv23_client_method(void);',

    # SSLv2 support is compiled out of some versions of OpenSSL.  These will
    # get special support when we generate the bindings so that if they are
    # available they will be wrapped, but if they are not they won't cause
    # problems (like link errors).
    'SSL_METHOD *SSLv2_method(void);',
    'SSL_METHOD *SSLv2_server_method(void);',
    'SSL_METHOD *SSLv2_client_method(void);',

    # SSL
    "SSL_CTX *SSL_set_SSL_CTX(SSL *ssl, SSL_CTX* ctx);",
    "SSL_SESSION *SSL_get1_session(SSL *ssl);",
    "int SSL_set_session(SSL *ssl, SSL_SESSION *session);",

    'int SSL_get_verify_mode(const SSL *ssl);',
    'void SSL_set_verify_depth(SSL *s, int depth);',
    'int SSL_get_verify_depth(const SSL *ssl);',
    'int (*SSL_get_verify_callback(const SSL *ssl))(int, X509_STORE_CTX *);',

    'long SSL_set_mode(SSL *ssl, long mode);',
    'long SSL_get_mode(SSL *ssl);',

    'long SSL_set_options(SSL *ssl, long options);',
    'long SSL_clear_options(SSL *ssl, long options);',
    'long SSL_get_options(SSL *ssl);',

    'void SSL_set_info_callback(SSL *ssl, void (*callback)());',
    'void (*SSL_get_info_callback(const SSL *ssl))();',

    'SSL *SSL_new(SSL_CTX *ctx);',
    'void SSL_free(SSL *ssl);',

    'int SSL_set_fd(SSL *ssl, int fd);',
    'void SSL_set_bio(SSL *ssl, BIO *rbio, BIO *wbio);',

    'void SSL_set_connect_state(SSL *ssl);',
    'void SSL_set_accept_state(SSL *ssl);',

    'void SSL_set_shutdown(SSL *ssl, int mode);',
    'int SSL_get_shutdown(const SSL *ssl);',

    'int SSL_pending(const SSL *ssl);',

    'int SSL_write(SSL *ssl, const void *buf, int num);',
    'int SSL_read(SSL *ssl, void *buf, int num);',
    'X509 *SSL_get_peer_certificate(const SSL *ssl);',
    'struct stack_st_X509 *SSL_get_peer_cert_chain(const SSL *ssl);',

    'int SSL_want_read(const SSL *ssl);',
    'int SSL_want_write(const SSL *ssl);',

    'int SSL_total_renegotiations(const SSL *ssl);',

    'int SSL_get_error(const SSL *ssl, int ret);',
    'int SSL_do_handshake(SSL *ssl);',
    'int SSL_shutdown(SSL *ssl);',
    'void SSL_set_shutdown(SSL *ssl, int mode);',
    'int SSL_get_shutdown(const SSL *ssl);',

    'struct stack_st_SSL_CIPHER *SSL_get_ciphers(const SSL *ssl);',
    'const char *SSL_get_cipher_list(const SSL *ssl, int priority);',

    'struct stack_st_X509_NAME *SSL_get_client_CA_list(const SSL *s);',

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

    'long SSL_CTX_set_options(SSL_CTX *ctx, long options);',
    'long SSL_CTX_clear_options(SSL_CTX *ctx, long options);',
    'long SSL_CTX_get_options(SSL_CTX *ctx);',

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
    "int SSL_CTX_use_certificate_file(SSL_CTX *ctx, const char *file, int type);",
    "int SSL_CTX_use_certificate_chain_file(SSL_CTX *ctx, const char *file);",

    "int SSL_CTX_use_PrivateKey(SSL_CTX *ctx, EVP_PKEY *pkey);",
    "int SSL_CTX_use_PrivateKey_file(SSL_CTX *ctx, const char *file, int type);",

    "struct stack_st_X509_NAME *SSL_CTX_get_client_CA_list(const SSL_CTX *ctx);",

    "void SSL_CTX_set_cert_store(SSL_CTX *ctx, X509_STORE *store);",
    "X509_STORE *SSL_CTX_get_cert_store(const SSL_CTX *ctx);",

    "int SSL_CTX_add_client_CA(SSL_CTX *ctx, X509 *cacert);",
    "void SSL_CTX_set_client_CA_list(SSL_CTX *ctx, struct stack_st_X509_NAME *list);",

    # X509_STORE_CTX
    "int    X509_STORE_CTX_get_error(X509_STORE_CTX *ctx);",
    "void   X509_STORE_CTX_set_error(X509_STORE_CTX *ctx,int s);",
    "int    X509_STORE_CTX_get_error_depth(X509_STORE_CTX *ctx);",
    "X509 * X509_STORE_CTX_get_current_cert(X509_STORE_CTX *ctx);",

    # SSL_SESSION
    "void SSL_SESSION_free(SSL_SESSION *session);",

    # SNI APIs were introduced in OpenSSL 1.0.0.  To continue to support
    # earlier versions some special handling of these is necessary.
    'void SSL_set_tlsext_host_name(SSL *ssl, char *name);',
    'const char *SSL_get_servername(const SSL *s, const int type);',
    'void SSL_CTX_set_tlsext_servername_callback(SSL_CTX *ctx, tlsext_servername_callback cb);',
]

C_CUSTOMIZATION = [
    """
#ifdef OPENSSL_NO_SSL2
static const int PYOPENSSL_NO_SSL2 = 1;
SSL_METHOD* (*SSLv2_method)(void) = NULL;
SSL_METHOD* (*SSLv2_client_method)(void) = NULL;
SSL_METHOD* (*SSLv2_server_method)(void) = NULL;
#else
static const int PYOPENSSL_NO_SSL2 = 0;
#endif
""",

    """
#ifdef SSL_CTRL_SET_TLSEXT_HOSTNAME
static const int PYOPENSSL_TLSEXT_HOSTNAME = 1;
#else
static const int PYOPENSSL_TLSEXT_HOSTNAME = 0;
void (*SSL_set_tlsext_host_name)(SSL *ssl, char *name) = NULL;
const char* (*SSL_get_servername)(const SSL *s, const int type) = NULL;
void (*SSL_CTX_set_tlsext_servername_callback)(SSL_CTX *ctx, tlsext_servername_callback cb) = NULL;
#endif
""",
    ]

