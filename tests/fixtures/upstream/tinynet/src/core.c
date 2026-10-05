#include "tinynet/tinynet.h"
#include "tinynet/version.h"

static int tinynet_ready;

tinynet_err_t tinynet_init(void)
{
    if (tinynet_ready) {
        return TINYNET_OK;
    }
    tinynet_ready = 1;
    return TINYNET_OK;
}

uint16_t tinynet_checksum(const uint8_t *data, size_t len)
{
    uint32_t sum = 0;
    size_t i;

    for (i = 0; i + 1 < len; i += 2) {
        sum += (uint32_t)((data[i] << 8) | data[i + 1]);
        if (sum > 0xFFFFu) {
            sum = (sum & 0xFFFFu) + 1u;
        }
    }
    if (i < len) {
        sum += (uint32_t)(data[i] << 8);
        if (sum > 0xFFFFu) {
            sum = (sum & 0xFFFFu) + 1u;
        }
    }
    return (uint16_t)(~sum & 0xFFFFu);
}
