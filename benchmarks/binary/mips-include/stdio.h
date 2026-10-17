#pragma once
#include <stddef.h>
#include <stdarg.h>
typedef struct _FILE FILE; extern FILE *stderr, *stdin, *stdout;
int printf(const char *, ...); int fprintf(FILE *, const char *, ...);
int snprintf(char *, size_t, const char *, ...); int vsnprintf(char *, size_t, const char *, va_list);
char *fgets(char *, int, FILE *); int fputs(const char *, FILE *); int puts(const char *);
#define EOF (-1)
FILE *fopen(const char *, const char *); int fclose(FILE *);
size_t fread(void *, size_t, size_t, FILE *); size_t fwrite(const void *, size_t, size_t, FILE *);
int fseek(FILE *, long, int); long ftell(FILE *); int fflush(FILE *); int fputc(int, FILE *);
#define SEEK_SET 0
#define SEEK_END 2
