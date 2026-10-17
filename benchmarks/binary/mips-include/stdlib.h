#pragma once
#include <stddef.h>
void *malloc(size_t); void *calloc(size_t, size_t); void free(void *); void *realloc(void *, size_t);
void abort(void); void exit(int);
int rand(void); void srand(unsigned); char *getenv(const char *); int atoi(const char *);
#define RAND_MAX 0x7fffffff
