#pragma once
#include <stddef.h>
void *malloc(size_t); void *calloc(size_t, size_t); void free(void *); void *realloc(void *, size_t);
void abort(void); void exit(int);
