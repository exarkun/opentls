INCLUDES = [
    "#include <openssl/crypto.h>",
]

TYPES = [
    "static const int CRYPTO_MEM_CHECK_ON;",
    "static const int CRYPTO_MEM_CHECK_OFF;",
    "static const int CRYPTO_MEM_CHECK_ENABLE;",
    "static const int CRYPTO_MEM_CHECK_DISABLE;",
]

FUNCTIONS = [
    "void CRYPTO_malloc_init();",
    "void CRYPTO_malloc_debug_init();",
    "int CRYPTO_mem_ctrl(int mode);",
    "void CRYPTO_mem_leaks(BIO *bio);",

    # XXX really belongs in ex_data.py
    "void CRYPTO_cleanup_all_ex_data();",
]
