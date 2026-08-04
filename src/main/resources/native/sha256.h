/* SHA-256 最小实现（零外部依赖，供壳 native 层使用） */
#ifndef SELFPROTECT_SHA256_H
#define SELFPROTECT_SHA256_H

#include <stdint.h>
#include <stddef.h>

typedef struct {
    uint8_t data[64];
    uint32_t datalen;
    uint64_t bitlen;
    uint32_t state[8];
} sha256_ctx;

void sha256_init(sha256_ctx *ctx);
void sha256_update(sha256_ctx *ctx, const uint8_t *in, size_t len);
void sha256_final(sha256_ctx *ctx, uint8_t out[32]);

void sha256_compute(const uint8_t *in, size_t len, uint8_t out[32]);

#endif /* SELFPROTECT_SHA256_H */
