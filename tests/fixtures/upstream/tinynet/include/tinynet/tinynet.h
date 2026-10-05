#ifndef TINYNET_H
#define TINYNET_H

#include <stddef.h>
#include <stdint.h>

typedef struct tinynet_buf {
    uint8_t *payload;
    size_t   len;
    size_t   capacity;
    struct tinynet_buf *next;
} tinynet_buf_t;

typedef enum {
    TINYNET_OK = 0,
    TINYNET_ERR_MEM = -1,
    TINYNET_ERR_ARG = -2,
    TINYNET_ERR_TIMEOUT = -3
} tinynet_err_t;

tinynet_err_t tinynet_init(void);
tinynet_buf_t *tinynet_buf_alloc(size_t capacity);
void tinynet_buf_free(tinynet_buf_t *buf);
tinynet_err_t tinynet_buf_append(tinynet_buf_t *buf, const uint8_t *data, size_t len);
uint16_t tinynet_checksum(const uint8_t *data, size_t len);

#endif /* TINYNET_H */
