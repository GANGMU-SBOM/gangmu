#pragma once
#include <stddef.h>
#include <stdarg.h>
typedef struct _FILE FILE; extern FILE *stderr, *stdin, *stdout;
int printf(const char *, ...); int fprintf(FILE *, const char *, ...);
int snprintf(char *, size_t, const char *, ...); int vsnprintf(char *, size_t, const char *, va_list);
char *fgets(char *, int, FILE *); int fputs(const char *, FILE *); int puts(const char *);
#define EOF (-1)
