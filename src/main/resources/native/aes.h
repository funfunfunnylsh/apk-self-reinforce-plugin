/*
 * AES-128-CBC 最小实现（零外部依赖，供壳 native 层使用）。
 * 仅实现解密路径（壳只需解密），密钥固定 128-bit。
 */
#ifndef SELFPROTECT_AES_H
#define SELFPROTECT_AES_H

#include <stdint.h>
#include <stddef.h>

/* ctx 为 11 轮轮密钥（16 字节 * 11） */
typedef struct {
    uint8_t rk[11 * 16];
} aes128_ctx;

void aes128_init_dec(aes128_ctx *ctx, const uint8_t key[16]);

/*
 * CBC 解密。in/out 可同 buffer，长度必须为 16 的倍数。
 */
void aes128_cbc_decrypt(const aes128_ctx *ctx, const uint8_t iv[16],
                        const uint8_t *in, uint8_t *out, size_t len);

/*
 * T-table 加速版 CBC 解密（约 10 倍提速）。其余约定同 aes128_cbc_decrypt。
 */
void aes128_cbc_decrypt_tab(const aes128_ctx *ctx, const uint8_t iv[16],
                            const uint8_t *in, uint8_t *out, size_t len);

/*
 * 去除 PKCS7 padding，返回明文长度；padding 非法返回 -1。
 */
int aes128_cbc_pkcs7_unpad(const uint8_t *buf, size_t len);

#endif /* SELFPROTECT_AES_H */
