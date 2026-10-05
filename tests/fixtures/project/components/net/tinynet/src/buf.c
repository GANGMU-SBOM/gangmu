#include "tinynet/tinynet.h"
#include <stdlib.h>
#include <string.h>

tinynet_buf_t *tinynet_buf_alloc(size_t capacity)
 {
tinynet_buf_t *buf;

if (capacity == 0 || capacity > (1u << 20)) {
    return NULL;
}
buf = (tinynet_buf_t *)calloc(1, sizeof(tinynet_buf_t));
if (buf == NULL) {
    return NULL;
}
buf->payload = (uint8_t *)calloc(1, capacity);
if (buf->payload == NULL) {
    free(buf);
    return NULL;
}
buf->capacity = capacity;
buf->len = 0;
buf->next = NULL;
return buf;
}

void tinynet_buf_free(tinynet_buf_t *buf)
 {
tinynet_buf_t *next;

while (buf != NULL) {
    next = buf->next;
    free(buf->payload);
    free(buf);
    buf = next;
}
}

tinynet_err_t tinynet_buf_append(tinynet_buf_t *buf, const uint8_t *data, size_t len)
 {
if (buf == NULL || data == NULL) {
    return TINYNET_ERR_ARG;
}
if (buf->len + len > buf->capacity) {
    return TINYNET_ERR_MEM;
}
memcpy(buf->payload + buf->len, data, len);
buf->len += len;
return TINYNET_OK;
}
