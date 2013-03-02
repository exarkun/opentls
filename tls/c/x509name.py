INCLUDES = [
    '#include <openssl/x509.h>',
]

TYPES = [
    'typedef ... X509_NAME;',
    'typedef ... X509_NAME_ENTRY;',
]

FUNCTIONS = [
    'int                 X509_NAME_entry_count(X509_NAME *name);',
    'X509_NAME_ENTRY *X509_NAME_get_entry(X509_NAME *name, int loc);',
    'ASN1_OBJECT *       X509_NAME_ENTRY_get_object(X509_NAME_ENTRY *ne);',
    'ASN1_STRING *       X509_NAME_ENTRY_get_data(X509_NAME_ENTRY *ne);',
    'unsigned long       X509_NAME_hash(X509_NAME *x);',

    'int i2d_X509_NAME(X509_NAME *a, unsigned char **pp);',
    'int X509_NAME_add_entry_by_NID(X509_NAME *name, int nid, int type, unsigned char *bytes, int len, int loc, int set);',
    'X509_NAME_ENTRY *X509_NAME_delete_entry(X509_NAME *name, int loc);',
    'void X509_NAME_ENTRY_free(X509_NAME_ENTRY* ent);',
    'int          X509_NAME_get_index_by_NID(X509_NAME *name,int nid,int lastpos);',
    'int          X509_NAME_cmp(const X509_NAME *a, const X509_NAME *b);',
    'char *           X509_NAME_oneline(X509_NAME *a,char *buf,int size);',
    'X509_NAME *X509_NAME_dup(X509_NAME *xn);',
    'void X509_NAME_free(X509_NAME *xn);',
]
