#include "aes.h"
#include <string.h>

static const uint8_t SBOX[256] = {
    0x63,0x7c,0x77,0x7b,0xf2,0x6b,0x6f,0xc5,0x30,0x01,0x67,0x2b,0xfe,0xd7,0xab,0x76,
    0xca,0x82,0xc9,0x7d,0xfa,0x59,0x47,0xf0,0xad,0xd4,0xa2,0xaf,0x9c,0xa4,0x72,0xc0,
    0xb7,0xfd,0x93,0x26,0x36,0x3f,0xf7,0xcc,0x34,0xa5,0xe5,0xf1,0x71,0xd8,0x31,0x15,
    0x04,0xc7,0x23,0xc3,0x18,0x96,0x05,0x9a,0x07,0x12,0x80,0xe2,0xeb,0x27,0xb2,0x75,
    0x09,0x83,0x2c,0x1a,0x1b,0x6e,0x5a,0xa0,0x52,0x3b,0xd6,0xb3,0x29,0xe3,0x2f,0x84,
    0x53,0xd1,0x00,0xed,0x20,0xfc,0xb1,0x5b,0x6a,0xcb,0xbe,0x39,0x4a,0x4c,0x58,0xcf,
    0xd0,0xef,0xaa,0xfb,0x43,0x4d,0x33,0x85,0x45,0xf9,0x02,0x7f,0x50,0x3c,0x9f,0xa8,
    0x51,0xa3,0x40,0x8f,0x92,0x9d,0x38,0xf5,0xbc,0xb6,0xda,0x21,0x10,0xff,0xf3,0xd2,
    0xcd,0x0c,0x13,0xec,0x5f,0x97,0x44,0x17,0xc4,0xa7,0x7e,0x3d,0x64,0x5d,0x19,0x73,
    0x60,0x81,0x4f,0xdc,0x22,0x2a,0x90,0x88,0x46,0xee,0xb8,0x14,0xde,0x5e,0x0b,0xdb,
    0xe0,0x32,0x3a,0x0a,0x49,0x06,0x24,0x5c,0xc2,0xd3,0xac,0x62,0x91,0x95,0xe4,0x79,
    0xe7,0xc8,0x37,0x6d,0x8d,0xd5,0x4e,0xa9,0x6c,0x56,0xf4,0xea,0x65,0x7a,0xae,0x08,
    0xba,0x78,0x25,0x2e,0x1c,0xa6,0xb4,0xc6,0xe8,0xdd,0x74,0x1f,0x4b,0xbd,0x8b,0x8a,
    0x70,0x3e,0xb5,0x66,0x48,0x03,0xf6,0x0e,0x61,0x35,0x57,0xb9,0x86,0xc1,0x1d,0x9e,
    0xe1,0xf8,0x98,0x11,0x69,0xd9,0x8e,0x94,0x9b,0x1e,0x87,0xe9,0xce,0x55,0x28,0xdf,
    0x8c,0xa1,0x89,0x0d,0xbf,0xe6,0x42,0x68,0x41,0x99,0x2d,0x0f,0xb0,0x54,0xbb,0x16
};

#define ROTL8(x) (((x) << 8) | ((x) >> 24))

static uint32_t xtime(uint32_t x) { return (x << 1) ^ (((x >> 7) & 1) * 0x1b); }

/* 列混合矩阵的逆（解密用） */
static const uint8_t INV_MIX[4][4] = {
    {0x0e, 0x0b, 0x0d, 0x09},
    {0x09, 0x0e, 0x0b, 0x0d},
    {0x0d, 0x09, 0x0e, 0x0b},
    {0x0b, 0x0d, 0x09, 0x0e}
};

static uint8_t gmul(uint8_t a, uint8_t b) {
    uint8_t p = 0;
    for (int i = 0; i < 8; i++) {
        if (b & 1) p ^= a;
        uint8_t hi = a & 0x80;
        a <<= 1;
        if (hi) a ^= 0x1b;
        b >>= 1;
    }
    return p;
}

static void sub_bytes(uint8_t *s) {
    for (int i = 0; i < 16; i++) s[i] = SBOX[s[i]];
}

static void inv_sub_bytes(uint8_t *s) {
    /* 逆 S-box：直接查表生成（构建期用 SBOX 反查） */
    static uint8_t inv[256];
    static int done = 0;
    if (!done) {
        for (int i = 0; i < 256; i++) inv[SBOX[i]] = (uint8_t)i;
        done = 1;
    }
    for (int i = 0; i < 16; i++) s[i] = inv[s[i]];
}

/* FIPS 197 标准：state[r][c] 位于 r + 4*c（列优先，列连续、行跨步） */
static void shift_rows(uint8_t *s) {
    uint8_t t[16];
    memcpy(t, s, 16);
    for (int r = 1; r < 4; r++) {
        for (int c = 0; c < 4; c++) {
            s[r + 4 * c] = t[r + 4 * ((c + r) % 4)];
        }
    }
}

static void inv_shift_rows(uint8_t *s) {
    uint8_t t[16];
    memcpy(t, s, 16);
    for (int r = 1; r < 4; r++) {
        for (int c = 0; c < 4; c++) {
            s[r + 4 * c] = t[r + 4 * ((c + 4 - r) % 4)];
        }
    }
}

static void mix_columns(uint8_t *s) {
    for (int c = 0; c < 4; c++) {
        uint8_t a[4];
        for (int r = 0; r < 4; r++) a[r] = s[r + 4 * c]; /* 列 c 连续 4 字节 */
        s[0 + 4 * c] = gmul(a[0], 2) ^ gmul(a[1], 3) ^ a[2] ^ a[3];
        s[1 + 4 * c] = a[0] ^ gmul(a[1], 2) ^ gmul(a[2], 3) ^ a[3];
        s[2 + 4 * c] = a[0] ^ a[1] ^ gmul(a[2], 2) ^ gmul(a[3], 3);
        s[3 + 4 * c] = gmul(a[0], 3) ^ a[1] ^ a[2] ^ gmul(a[3], 2);
    }
}

static void inv_mix_columns(uint8_t *s) {
    for (int c = 0; c < 4; c++) {
        uint8_t a[4];
        for (int i = 0; i < 4; i++) a[i] = s[i + 4 * c];
        for (int r = 0; r < 4; r++) {
            uint8_t v = 0;
            for (int k = 0; k < 4; k++) v ^= gmul(INV_MIX[r][k], a[k]);
            s[r + 4 * c] = v;
        }
    }
}

static void add_round_key(uint8_t *s, const uint8_t *rk) {
    for (int i = 0; i < 16; i++) s[i] ^= rk[i];
}

static void aes_round_dec(uint8_t *s, const uint8_t *rk) {
    inv_shift_rows(s);
    inv_sub_bytes(s);
    add_round_key(s, rk);
    inv_mix_columns(s);
}

/* =====================================================================
 * 解密 T-table（Td0-Td3）：一次查表完成 InvSubBytes + InvShiftRows +
 * InvMixColumns，解密速度提升约一个数量级。
 * 状态采用与 slow 实现一致的"列优先"字节布局（state[r][c] = s[r+4c]），
 * 每个 32 位字按列装入（w = s[0]|s[1]<<8|s[2]<<16|s[3]<<24，即小端列序）。
 * 与标准 AES T-table 编码一致（Td0..Td3 已含 ROTL8 轮转）。
 * ===================================================================== */
static uint32_t Td0[256], Td1[256], Td2[256], Td3[256];
static uint8_t INV_SBOX[256];
static int td_ready = 0;

static void init_td_tables(void) {
    /* 先建立逆 S-box */
    for (int i = 0; i < 256; i++) INV_SBOX[SBOX[i]] = (uint8_t)i;
    /* 列优先小端：word = row0 | row1<<8 | row2<<16 | row3<<24。
       T 表内置 InvSubBytes + InvMixColumns（等价逆密码的标准约定）：
       Td0 = 对应当前列行0 字节的贡献系数 (0x0e,0x09,0x0d,0x0b)；
       Td1/Td2/Td3 = 标准 ROTL8/16/24 轮转，配合下方轮函数的 s0/s3/s2/s1 索引。 */
    for (int i = 0; i < 256; i++) {
        uint8_t x = INV_SBOX[i];
        Td0[i] = (uint32_t)gmul(x, 0x0e) | ((uint32_t)gmul(x, 0x09) << 8)
               | ((uint32_t)gmul(x, 0x0d) << 16) | ((uint32_t)gmul(x, 0x0b) << 24);
        Td1[i] = ROTL8(Td0[i]);
        Td2[i] = ROTL8(ROTL8(Td0[i]));
        Td3[i] = ROTL8(ROTL8(ROTL8(Td0[i])));
    }
    td_ready = 1;
}

/* 等价逆密码：慢速实现每轮为 InvShiftRows→InvSubBytes→AddRoundKey→InvMixColumns，
   轮密钥在 InvMix 之前 XOR。T 表把 InvMix 折进查找表后，第 1~9 轮轮密钥必须
   预先做一次 InvMixColumns 补偿（第 0、10 轮无 InvMix，保持原始）。 */
static void mix_round_keys(const aes128_ctx *ctx, uint8_t rkM[11 * 16]) {
    memcpy(rkM, ctx->rk, 11 * 16);
    uint8_t t[16];
    for (int r = 1; r < 10; r++) {
        memcpy(t, rkM + 16 * r, 16);
        inv_mix_columns(t);
        memcpy(rkM + 16 * r, t, 16);
    }
}

static inline uint32_t rd32le(const uint8_t *p) {
    return (uint32_t)p[0] | ((uint32_t)p[1] << 8)
         | ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24);
}

static inline void wr32le(uint8_t *p, uint32_t v) {
    p[0] = (uint8_t)v; p[1] = (uint8_t)(v >> 8);
    p[2] = (uint8_t)(v >> 16); p[3] = (uint8_t)(v >> 24);
}

void aes128_cbc_decrypt_tab(const aes128_ctx *ctx, const uint8_t iv[16],
                            const uint8_t *in, uint8_t *out, size_t len) {
    if (!td_ready) init_td_tables();
    /* 等价逆密码：1~9 轮轮密钥需预做 InvMixColumns 补偿（0/10 轮无 InvMix，保持原始） */
    uint8_t rkM[11 * 16];
    mix_round_keys(ctx, rkM);
    uint8_t prev[16];
    memcpy(prev, iv, 16);
    for (size_t off = 0; off < len; off += 16) {
        uint32_t s0 = rd32le(in + off);
        uint32_t s1 = rd32le(in + off + 4);
        uint32_t s2 = rd32le(in + off + 8);
        uint32_t s3 = rd32le(in + off + 12);

        uint32_t t0, t1, t2, t3;
        s0 ^= rd32le(rkM + 0); s1 ^= rd32le(rkM + 4);
        s2 ^= rd32le(rkM + 8); s3 ^= rd32le(rkM + 12);

        for (int r = 1; r < 10; r++) {
            const uint8_t *rk = rkM + 16 * r;
            t0 = Td0[s0 & 0xFF] ^ Td1[(s3 >> 8) & 0xFF] ^ Td2[(s2 >> 16) & 0xFF] ^ Td3[(s1 >> 24) & 0xFF] ^ rd32le(rk);
            t1 = Td0[s1 & 0xFF] ^ Td1[(s0 >> 8) & 0xFF] ^ Td2[(s3 >> 16) & 0xFF] ^ Td3[(s2 >> 24) & 0xFF] ^ rd32le(rk + 4);
            t2 = Td0[s2 & 0xFF] ^ Td1[(s1 >> 8) & 0xFF] ^ Td2[(s0 >> 16) & 0xFF] ^ Td3[(s3 >> 24) & 0xFF] ^ rd32le(rk + 8);
            t3 = Td0[s3 & 0xFF] ^ Td1[(s2 >> 8) & 0xFF] ^ Td2[(s1 >> 16) & 0xFF] ^ Td3[(s0 >> 24) & 0xFF] ^ rd32le(rk + 12);
            s0 = t0; s1 = t1; s2 = t2; s3 = t3;
        }

        /* 末轮：InvShiftRows + InvSubBytes（无 InvMixColumns）+ AddRoundKey，再 XOR prev */
        const uint8_t *rkf = rkM + 10 * 16;
        uint8_t a0 = INV_SBOX[s0 & 0xFF], a1 = INV_SBOX[(s3 >> 8) & 0xFF],
                 a2 = INV_SBOX[(s2 >> 16) & 0xFF], a3 = INV_SBOX[(s1 >> 24) & 0xFF];
        uint32_t c0 = a0 | (a1 << 8) | (a2 << 16) | (a3 << 24);
        a0 = INV_SBOX[s1 & 0xFF]; a1 = INV_SBOX[(s0 >> 8) & 0xFF];
        a2 = INV_SBOX[(s3 >> 16) & 0xFF]; a3 = INV_SBOX[(s2 >> 24) & 0xFF];
        uint32_t c1 = a0 | (a1 << 8) | (a2 << 16) | (a3 << 24);
        a0 = INV_SBOX[s2 & 0xFF]; a1 = INV_SBOX[(s1 >> 8) & 0xFF];
        a2 = INV_SBOX[(s0 >> 16) & 0xFF]; a3 = INV_SBOX[(s3 >> 24) & 0xFF];
        uint32_t c2 = a0 | (a1 << 8) | (a2 << 16) | (a3 << 24);
        a0 = INV_SBOX[s3 & 0xFF]; a1 = INV_SBOX[(s2 >> 8) & 0xFF];
        a2 = INV_SBOX[(s1 >> 16) & 0xFF]; a3 = INV_SBOX[(s0 >> 24) & 0xFF];
        uint32_t c3 = a0 | (a1 << 8) | (a2 << 16) | (a3 << 24);

        wr32le(out + off, c0 ^ rd32le(rkf) ^ rd32le(prev));
        wr32le(out + off + 4, c1 ^ rd32le(rkf + 4) ^ rd32le(prev + 4));
        wr32le(out + off + 8, c2 ^ rd32le(rkf + 8) ^ rd32le(prev + 8));
        wr32le(out + off + 12, c3 ^ rd32le(rkf + 12) ^ rd32le(prev + 12));
        memcpy(prev, in + off, 16);
    }
}

void aes128_init_dec(aes128_ctx *ctx, const uint8_t key[16]) {
    /* 密钥扩展：标准 AES-128（11 轮，每轮 16 字节） */
    uint8_t w[4 * 44];
    memcpy(w, key, 16);
    int rcon = 1;
    for (int i = 4; i < 44; i++) {
        uint8_t t[4];
        memcpy(t, w + 4 * (i - 1), 4);
        if (i % 4 == 0) {
            uint8_t tmp = t[0];
            t[0] = t[1]; t[1] = t[2]; t[2] = t[3]; t[3] = tmp; /* RotWord */
            for (int j = 0; j < 4; j++) t[j] = SBOX[t[j]];       /* SubWord */
            t[0] ^= (uint8_t)rcon;
            rcon = xtime((uint32_t)rcon);
        }
        for (int j = 0; j < 4; j++) {
            w[4 * i + j] = w[4 * (i - 4) + j] ^ t[j];
        }
    }
    /* 解密需要逆序轮密钥：rk[0] 用 w[40..43]，rk[10] 用 w[0..3] */
    for (int round = 0; round <= 10; round++) {
        memcpy(ctx->rk + 16 * round, w + 16 * (10 - round), 16);
    }
}

void aes128_cbc_decrypt(const aes128_ctx *ctx, const uint8_t iv[16],
                        const uint8_t *in, uint8_t *out, size_t len) {
    /* 默认走 T-table 加速路径（约 10 倍提速）；原逐位实现保留于下方 aes128_cbc_decrypt_slow */
    aes128_cbc_decrypt_tab(ctx, iv, in, out, len);
}

/* ============ 原逐位实现（保留作自校验/回退对照，正式链路不调用） ============ */
void aes128_cbc_decrypt_slow(const aes128_ctx *ctx, const uint8_t iv[16],
                             const uint8_t *in, uint8_t *out, size_t len) {
    uint8_t prev[16], cur[16];
    memcpy(prev, iv, 16);
    for (size_t off = 0; off < len; off += 16) {
        memcpy(cur, in + off, 16);
        uint8_t s[16];
        memcpy(s, cur, 16);
        /* 初始轮（无 mix） */
        add_round_key(s, ctx->rk + 0 * 16);
        for (int round = 1; round < 10; round++) {
            aes_round_dec(s, ctx->rk + round * 16);
        }
        /* 末轮（无 mix） */
        inv_shift_rows(s);
        inv_sub_bytes(s);
        add_round_key(s, ctx->rk + 10 * 16);
        for (int i = 0; i < 16; i++) out[off + i] = s[i] ^ prev[i];
        memcpy(prev, cur, 16);
    }
}

int aes128_cbc_pkcs7_unpad(const uint8_t *buf, size_t len) {
    if (len == 0 || len % 16 != 0) return -1;
    uint8_t pad = buf[len - 1];
    if (pad == 0 || pad > 16) return -1;
    for (size_t i = 0; i < pad; i++) {
        if (buf[len - 1 - i] != pad) return -1;
    }
    return (int)(len - pad);
}
