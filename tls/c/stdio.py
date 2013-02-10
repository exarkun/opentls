INCLUDES = [
    '#include <stdio.h>',
]

TYPES = [
#    'typedef ... FILE;',
]

FUNCTIONS = [
    'FILE *fdopen(int fildes, const char *mode);',
    'FILE *fopen(const char *restrict filename, const char *restrict mode);',
    'FILE *freopen(const char *restrict filename, const char *restrict mode, FILE *restrict stream);',
]
