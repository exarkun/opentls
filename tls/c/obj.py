INCLUDES = [
    '#include <openssl/objects.h>',
]

TYPES = [
    'static const int OBJ_NAME_TYPE_UNDEF;',
    'static const int OBJ_NAME_TYPE_MD_METH;',
    'static const int OBJ_NAME_TYPE_CIPHER_METH;',
    'static const int OBJ_NAME_TYPE_PKEY_METH;',
    'static const int OBJ_NAME_TYPE_COMP_METH;',
    'static const int OBJ_NAME_TYPE_NUM;',
    'struct obj_name_st { int type; int alias; const char *name; const char *data; ...; };',
    'typedef struct obj_name_st OBJ_NAME;',
]

FUNCTIONS = [
    'ASN1_OBJECT *OBJ_nid2obj(int n);',
    'const char *OBJ_nid2ln(int n);',
    'const char *OBJ_nid2sn(int n);',
    'int OBJ_obj2nid(const ASN1_OBJECT *o);',
    'int OBJ_ln2nid(const char *ln);',
    'int OBJ_sn2nid(const char *sn);',
    'int OBJ_txt2nid(const char *s);',
    'ASN1_OBJECT * OBJ_txt2obj(const char *s, int no_name);',
    'int OBJ_obj2txt(char *buf, int buf_len, const ASN1_OBJECT *a, int no_name);',
    'int OBJ_cmp(const ASN1_OBJECT *a,const ASN1_OBJECT *b);',
    'ASN1_OBJECT * OBJ_dup(const ASN1_OBJECT *o);',
    'int OBJ_create(const char *oid,const char *sn,const char *ln);',
    'void OBJ_cleanup(void);',
    'int OBJ_NAME_init(void);',
    'void OBJ_NAME_do_all(int type,void (*fn)(const OBJ_NAME *,void *arg), void *arg);',
    'void OBJ_NAME_do_all_sorted(int type,void (*fn)(const OBJ_NAME *,void *arg), void *arg);',
]
