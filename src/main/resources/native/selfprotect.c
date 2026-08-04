/*
 * libselfprotect.so —— 壳 native 层
 *
 * 职责：
 *  1. native 反调试（ptrace TRACEME 自附加 + TracerPid 轮询 + frida/gadget 特征 + 27042 端口）
 *  2. 反模拟器 / 反 root
 *  3. AES-128-CBC 解密 payload（密钥编译进 so，混淆存储）
 *  4. SHA-256 完整性计算
 *  5. memfd_create（API<26 时载荷不落盘）
 *
 * 编译：NDK clang，-fvisibility=hidden，零外部依赖（不链接 OpenSSL）。
 */
#include <jni.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <pthread.h>
#include <sys/ptrace.h>
#include <sys/socket.h>
#include <sys/syscall.h>
#include <sys/stat.h>
#include <arpa/inet.h>
#include <errno.h>
#include <android/log.h>

#include "aes.h"
#include "sha256.h"

#define LOG_TAG "SelfProtectNative"
#define LOGI(...) __android_log_print(ANDROID_LOG_INFO, LOG_TAG, __VA_ARGS__)
#define LOGW(...) __android_log_print(ANDROID_LOG_WARN, LOG_TAG, __VA_ARGS__)

/* 密钥掩码常量：构建期由 NativeBuilder 注入 key.h（SP_KEY_PART / SP_KEY_MASK） */
#include "key.h"

/* ---------------- 字符串混淆（XOR 0x5A，防 strings 直读） ---------------- */
#define XC 0x5A
#define OBF_DECL(name, lit) \
    static const unsigned char name[] = { /* 手写 XOR 混淆 */ }
/* 运行时解出字符串到 buf（调用方保证 buf 足够大） */
static void obf_str(char *out, const volatile unsigned char *in) {
    while (*in) {
        *out++ = (char)(*in++ ^ XC);
    }
    *out = 0;
}

/* 预混淆字符串（构建期生成：字符 ^ 0x5A） */
static const volatile unsigned char s_frida[]        = {'f'^XC,'r'^XC,'i'^XC,'d'^XC,'a'^XC,'-'^XC,'s'^XC,'e'^XC,'r'^XC,'v'^XC,'e'^XC,'r'^XC,'.'^XC,'s'^XC,'o'^XC,0};
static const volatile unsigned char s_gum[]          = {'g'^XC,'u'^XC,'m'^XC,'-'^XC,'j'^XC,'s'^XC,'-'^XC,'l'^XC,'o'^XC,'o'^XC,'p'^XC,0};
static const volatile unsigned char s_gadget[]       = {'g'^XC,'a'^XC,'d'^XC,'g'^XC,'e'^XC,'t'^XC,'.'^XC,'s'^XC,'o'^XC,0};
static const volatile unsigned char s_linjector[]    = {'l'^XC,'i'^XC,'n'^XC,'j'^XC,'e'^XC,'c'^XC,'t'^XC,'o'^XC,'r'^XC,0};
static const volatile unsigned char s_xposed[]       = {'x'^XC,'p'^XC,'o'^XC,'s'^XC,'e'^XC,'d'^XC,0};
static const volatile unsigned char s_substrate[]    = {'s'^XC,'u'^XC,'b'^XC,'s'^XC,'t'^XC,'r'^XC,'a'^XC,'t'^XC,'e'^XC,0};
static const volatile unsigned char s_zygisk[]       = {'z'^XC,'y'^XC,'g'^XC,'i'^XC,'s'^XC,'k'^XC,0};
static const volatile unsigned char s_ports[]        = {'2'^XC,'7'^XC,'0'^XC,'4'^XC,'2'^XC,0};
static const volatile unsigned char s_tracerpid[]    = {'T'^XC,'r'^XC,'a'^XC,'c'^XC,'e'^XC,'r'^XC,'P'^XC,'i'^XC,'d'^XC,0};
static const volatile unsigned char s_status_path[]  = {'/'^XC,'p'^XC,'r'^XC,'o'^XC,'c'^XC,'/'^XC,'s'^XC,'e'^XC,'l'^XC,'f'^XC,'/'^XC,'s'^XC,'t'^XC,'a'^XC,'t'^XC,'u'^XC,'s'^XC,0};
static const volatile unsigned char s_maps_path[]    = {'/'^XC,'p'^XC,'r'^XC,'o'^XC,'c'^XC,'/'^XC,'s'^XC,'e'^XC,'l'^XC,'f'^XC,'/'^XC,'m'^XC,'a'^XC,'p'^XC,'s'^XC,0};
static const volatile unsigned char s_qemu_prop[]    = {'r'^XC,'o'^XC,'.'^XC,'k'^XC,'e'^XC,'r'^XC,'n'^XC,'e'^XC,'l'^XC,'.'^XC,'q'^XC,'e'^XC,'m'^XC,'u'^XC,0};
static const volatile unsigned char s_hardware_prop[]= {'r'^XC,'o'^XC,'.'^XC,'h'^XC,'a'^XC,'r'^XC,'d'^XC,'w'^XC,'a'^XC,'r'^XC,'e'^XC,0};
static const volatile unsigned char s_product_prop[] = {'r'^XC,'o'^XC,'.'^XC,'p'^XC,'r'^XC,'o'^XC,'d'^XC,'u'^XC,'c'^XC,'t'^XC,'.'^XC,'m'^XC,'o'^XC,'d'^XC,'e'^XC,'l'^XC,0};
static const volatile unsigned char s_goldfish[]     = {'g'^XC,'o'^XC,'l'^XC,'d'^XC,'f'^XC,'i'^XC,'s'^XC,'h'^XC,0};
static const volatile unsigned char s_ranchu[]       = {'r'^XC,'a'^XC,'n'^XC,'c'^XC,'h'^XC,'u'^XC,0};
static const volatile unsigned char s_vbox[]         = {'v'^XC,'b'^XC,'o'^XC,'x'^XC,'8'^XC,'6'^XC,0};
static const volatile unsigned char s_sdk_model[]    = {'s'^XC,'d'^XC,'k'^XC,0};
static const volatile unsigned char s_emulator[]     = {'e'^XC,'m'^XC,'u'^XC,'l'^XC,'a'^XC,'t'^XC,'o'^XC,'r'^XC,0};
static const volatile unsigned char s_tty_drivers[]  = {'/'^XC,'p'^XC,'r'^XC,'o'^XC,'c'^XC,'/'^XC,'t'^XC,'t'^XC,'y'^XC,'/'^XC,'d'^XC,'r'^XC,'i'^XC,'v'^XC,'e'^XC,'r'^XC,'s'^XC,0};
static const volatile unsigned char s_su_bin[]       = {'/'^XC,'s'^XC,'y'^XC,'s'^XC,'t'^XC,'e'^XC,'m'^XC,'/'^XC,'b'^XC,'i'^XC,'n'^XC,'/'^XC,'s'^XC,'u'^XC,0};
static const volatile unsigned char s_su_xbin[]      = {'/'^XC,'s'^XC,'y'^XC,'s'^XC,'t'^XC,'e'^XC,'m'^XC,'/'^XC,'x'^XC,'b'^XC,'i'^XC,'n'^XC,'/'^XC,'s'^XC,'u'^XC,0};
static const volatile unsigned char s_su_sbin[]      = {'/'^XC,'s'^XC,'b'^XC,'i'^XC,'n'^XC,'/'^XC,'s'^XC,'u'^XC,0};
static const volatile unsigned char s_magisk_dir[]   = {'/'^XC,'d'^XC,'a'^XC,'t'^XC,'a'^XC,'/'^XC,'a'^XC,'d'^XC,'b'^XC,'/'^XC,'m'^XC,'a'^XC,'g'^XC,'i'^XC,'s'^XC,'k'^XC,0};
static const volatile unsigned char s_magisk_sbin[]  = {'/'^XC,'s'^XC,'b'^XC,'i'^XC,'n'^XC,'/'^XC,'.'^XC,'m'^XC,'a'^XC,'g'^XC,'i'^XC,'s'^XC,'k'^XC,0};
static const volatile unsigned char s_mounts_path[]  = {'/'^XC,'p'^XC,'r'^XC,'o'^XC,'c'^XC,'/'^XC,'s'^XC,'e'^XC,'l'^XC,'f'^XC,'/'^XC,'m'^XC,'o'^XC,'u'^XC,'n'^XC,'t'^XC,'s'^XC,0};
static const volatile unsigned char s_magisk[]       = {'m'^XC,'a'^XC,'g'^XC,'i'^XC,'s'^XC,'k'^XC,0};

/* ---------------- 文件/属性辅助 ---------------- */

static char *read_file_into(const char *path, size_t *out_len) {
    int fd = open(path, O_RDONLY | O_CLOEXEC);
    if (fd < 0) return NULL;
    size_t cap = 4096, len = 0;
    char *buf = (char *)malloc(cap);
    if (!buf) { close(fd); return NULL; }
    ssize_t n;
    while ((n = read(fd, buf + len, cap - len)) > 0) {
        len += (size_t)n;
        if (len + 512 > cap) {
            cap *= 2;
            char *nb = (char *)realloc(buf, cap);
            if (!nb) { free(buf); close(fd); return NULL; }
            buf = nb;
        }
    }
    close(fd);
    if (n < 0) { free(buf); return NULL; }
    buf[len] = 0;
    if (out_len) *out_len = len;
    return buf;
}

static int get_prop(const char *key, char *out, size_t out_size) {
    /* 用 bionic __system_property_get（android/log.h 之外，需要 <sys/system_properties.h>） */
    extern int __system_property_get(const char *name, char *value);
    if (!out || out_size == 0) return 0;
    int n = __system_property_get(key, out);
    if (n < 0) n = 0;
    if ((size_t)n >= out_size) n = (int)(out_size - 1);
    out[n] = 0;
    return n;
}

static int str_contains(const char *haystack, const char *needle) {
    return haystack && needle && strstr(haystack, needle) != NULL;
}

/* ---------------- 反调试 ---------------- */

static int check_tracerpid(void) {
    char path[64];
    obf_str(path, s_status_path);
    char *st = read_file_into(path, NULL);
    if (!st) return 0;
    char key[16];
    obf_str(key, s_tracerpid);
    const char *p = strstr(st, key);
    int tracer = 0;
    if (p) {
        p += strlen(key);
        while (*p == ' ' || *p == '\t' || *p == ':') p++;
        while (*p >= '0' && *p <= '9') {
            tracer = tracer * 10 + (*p - '0');
            p++;
        }
    }
    free(st);
    return tracer;
}

static int check_hook_maps(void) {
    char path[64];
    obf_str(path, s_maps_path);
    char *maps = read_file_into(path, NULL);
    if (!maps) return 0;
    int hit = 0;
    char pat[64];
    /* frida / gum-js-loop / gadget / linjector / xposed / substrate / zygisk */
    obf_str(pat, s_frida);    if (str_contains(maps, pat)) hit = 1;
    obf_str(pat, s_gum);      if (str_contains(maps, pat)) hit = 1;
    obf_str(pat, s_gadget);   if (str_contains(maps, pat)) hit = 1;
    obf_str(pat, s_linjector);if (str_contains(maps, pat)) hit = 1;
    obf_str(pat, s_xposed);   if (str_contains(maps, pat)) hit = 1;
    obf_str(pat, s_substrate);if (str_contains(maps, pat)) hit = 1;
    obf_str(pat, s_zygisk);   if (str_contains(maps, pat)) hit = 1;
    free(maps);
    return hit;
}

static int check_frida_port(void) {
    /* 探测 frida 默认端口 27042（本机 + 127.0.0.1） */
    char port_str[8];
    obf_str(port_str, s_ports);
    int port = atoi(port_str);
    if (port <= 0) return 0;
    /* 尝试连接本地端口：connect 成功即认为有 frida-server 监听 */
    int s = socket(AF_INET, SOCK_STREAM, 0);
    if (s < 0) return 0;
    struct sockaddr_in sa;
    memset(&sa, 0, sizeof(sa));
    sa.sin_family = AF_INET;
    sa.sin_port = htons((uint16_t)port);
    sa.sin_addr.s_addr = htonl(0x7f000001); /* 127.0.0.1 */
    int rc = connect(s, (struct sockaddr *)&sa, sizeof(sa));
    close(s);
    return rc == 0;
}

/* 后台监控线程：TracerPid / hook maps / frida 端口，命中即静默退出 */
static void *monitor_thread(void *arg) {
    (void)arg;
    while (1) {
        usleep(800 * 1000);
        if (check_tracerpid() != 0) _exit(0);
        if (check_hook_maps()) _exit(0);
        if (check_frida_port()) _exit(0);
    }
    return NULL;
}

/* 一次性反调试：ptrace TRACEME + TracerPid + maps + 端口。返回 0 通过，非 0 命中原因码 */
static int anti_debug_once(void) {
    /* TRACEME 自附加：成功后本进程无法再被其他调试器附加；失败说明已被附加 */
    if (ptrace(PTRACE_TRACEME, 0, NULL, NULL) == -1) {
        return 1;
    }
    if (check_tracerpid() != 0) return 2;
    if (check_hook_maps()) return 4;
    if (check_frida_port()) return 8;
    return 0;
}

/* ---------------- 反模拟器 / 反 root ---------------- */

static int detect_emulator(void) {
    char v[128];
    /* ro.kernel.qemu == 1 */
    char key[32];
    obf_str(key, s_qemu_prop);
    if (get_prop(key, v, sizeof(v)) > 0 && strcmp(v, "1") == 0) return 1;
    /* ro.hardware: goldfish / ranchu / vbox86 */
    obf_str(key, s_hardware_prop);
    if (get_prop(key, v, sizeof(v)) > 0) {
        char pat[16];
        obf_str(pat, s_goldfish);  if (str_contains(v, pat)) return 2;
        obf_str(pat, s_ranchu);    if (str_contains(v, pat)) return 2;
        obf_str(pat, s_vbox);      if (str_contains(v, pat)) return 2;
    }
    /* ro.product.model: sdk / google_sdk / emulator */
    obf_str(key, s_product_prop);
    if (get_prop(key, v, sizeof(v)) > 0) {
        char pat[16];
        obf_str(pat, s_sdk_model); if (str_contains(v, pat)) return 3;
        obf_str(pat, s_emulator);  if (str_contains(v, pat)) return 3;
    }
    /* /proc/tty/drivers 含 goldfish */
    char path[64];
    obf_str(path, s_tty_drivers);
    char *tty = read_file_into(path, NULL);
    if (tty) {
        char pat[16];
        obf_str(pat, s_goldfish);
        if (str_contains(tty, pat)) { free(tty); return 4; }
        free(tty);
    }
    return 0;
}

static int detect_root(void) {
    char p[64];
    struct stat st;
    /* su 常见路径 */
    obf_str(p, s_su_bin);   if (access(p, F_OK) == 0) return 1;
    obf_str(p, s_su_xbin);  if (access(p, F_OK) == 0) return 1;
    obf_str(p, s_su_sbin);  if (access(p, F_OK) == 0) return 1;
    /* Magisk */
    obf_str(p, s_magisk_dir);  if (stat(p, &st) == 0) return 2;
    obf_str(p, s_magisk_sbin); if (stat(p, &st) == 0) return 2;
    /* /proc/self/mounts 含 magisk（部分设备 magisk 挂载） */
    obf_str(p, s_mounts_path);
    char *m = read_file_into(p, NULL);
    if (m) {
        char pat[16];
        obf_str(pat, s_magisk);
        if (str_contains(m, pat)) { free(m); return 3; }
        free(m);
    }
    return 0;
}

/* ---------------- payload 解密 ---------------- */

static void derive_key(uint8_t key[16]) {
    /* key = KEY_PART ^ KEY_MASK（常量来自 key.h，均为混淆字节） */
    for (int i = 0; i < 16; i++) {
        key[i] = (uint8_t)(SP_KEY_PART[i] ^ SP_KEY_MASK[i]);
    }
}

/* ---------------- memfd（API<26 不落盘） ---------------- */

static int create_memfd(const char *name, const uint8_t *data, size_t len) {
#if defined(__aarch64__)
    long fd = syscall(279, name, 0x0001 /* MFD_CLOEXEC */); /* SYS_memfd_create arm64 */
#else
    long fd = syscall(385, name, 0x0001); /* SYS_memfd_create arm(32) */
#endif
    if (fd < 0) return -1;
    size_t off = 0;
    while (off < len) {
        ssize_t n = write((int)fd, data + off, len - off);
        if (n <= 0) { close((int)fd); return -1; }
        off += (size_t)n;
    }
    lseek((int)fd, 0, SEEK_SET);
    return (int)fd;
}

/* ---------------- JNI ---------------- */

/* init(flags) -> 0 通过；非 0 命中位组合：1=反调试 2=模拟器 4=root */
JNIEXPORT jint JNICALL
Java_com_selfprotect_ShellNative_init(JNIEnv *env, jclass clazz, jint flags) {
    (void)env; (void)clazz;
    int result = 0;
    if (flags & 1) {
        int r = anti_debug_once();
        if (r) result |= 1;
        /* 启动后台监控线程 */
        pthread_t tid;
        if (pthread_create(&tid, NULL, monitor_thread, NULL) == 0) {
            pthread_detach(tid);
        }
    }
    if (flags & 2) {
        if (detect_emulator()) result |= 2;
    }
    if (flags & 4) {
        if (detect_root()) result |= 4;
    }
    return result;
}

/* decryptPayload(byte[] encrypted) -> byte[] 明文（zip），失败返回 null */
JNIEXPORT jbyteArray JNICALL
Java_com_selfprotect_ShellNative_decryptPayload(JNIEnv *env, jclass clazz, jbyteArray encrypted) {
    (void)clazz;
    if (!encrypted) return NULL;
    jsize in_len = (*env)->GetArrayLength(env, encrypted);
    if (in_len < 32) return NULL;
    jbyte *in = (*env)->GetByteArrayElements(env, encrypted, NULL);
    if (!in) return NULL;

    const uint8_t *iv = (const uint8_t *)in;              /* 前 16 字节 IV */
    size_t ct_len = (size_t)(in_len - 16);
    uint8_t *ct = (uint8_t *)in + 16;

    uint8_t key[16];
    derive_key(key);
    aes128_ctx ctx;
    aes128_init_dec(&ctx, key);
    memset(key, 0, sizeof(key));

    uint8_t *plain = (uint8_t *)malloc(ct_len);
    if (!plain) {
        (*env)->ReleaseByteArrayElements(env, encrypted, in, JNI_ABORT);
        return NULL;
    }
    aes128_cbc_decrypt(&ctx, iv, ct, plain, ct_len);
    int plen = aes128_cbc_pkcs7_unpad(plain, ct_len);
    if (plen <= 0) {
        free(plain);
        (*env)->ReleaseByteArrayElements(env, encrypted, in, JNI_ABORT);
        return NULL;
    }

    jbyteArray out = (*env)->NewByteArray(env, (jsize)plen);
    if (out) {
        (*env)->SetByteArrayRegion(env, out, 0, (jsize)plen, (const jbyte *)plain);
    }
    free(plain);
    (*env)->ReleaseByteArrayElements(env, encrypted, in, JNI_ABORT);
    return out;
}

/* sha256(byte[] data) -> byte[32] */
JNIEXPORT jbyteArray JNICALL
Java_com_selfprotect_ShellNative_sha256(JNIEnv *env, jclass clazz, jbyteArray data) {
    (void)clazz;
    if (!data) return NULL;
    jsize len = (*env)->GetArrayLength(env, data);
    jbyte *in = (*env)->GetByteArrayElements(env, data, NULL);
    if (!in) return NULL;
    uint8_t digest[32];
    sha256_compute((const uint8_t *)in, (size_t)len, digest);
    (*env)->ReleaseByteArrayElements(env, data, in, JNI_ABORT);
    jbyteArray out = (*env)->NewByteArray(env, 32);
    if (out) {
        (*env)->SetByteArrayRegion(env, out, 0, 32, (const jbyte *)digest);
    }
    return out;
}

/* createMemfd(String name, byte[] data) -> fd；失败 -1 */
JNIEXPORT jint JNICALL
Java_com_selfprotect_ShellNative_createMemfd(JNIEnv *env, jclass clazz, jstring name, jbyteArray data) {
    (void)clazz;
    if (!name || !data) return -1;
    const char *cname = (*env)->GetStringUTFChars(env, name, NULL);
    jsize len = (*env)->GetArrayLength(env, data);
    jbyte *in = (*env)->GetByteArrayElements(env, data, NULL);
    if (!cname || !in) {
        if (cname) (*env)->ReleaseStringUTFChars(env, name, cname);
        if (in) (*env)->ReleaseByteArrayElements(env, data, in, JNI_ABORT);
        return -1;
    }
    int fd = create_memfd(cname, (const uint8_t *)in, (size_t)len);
    (*env)->ReleaseStringUTFChars(env, name, cname);
    (*env)->ReleaseByteArrayElements(env, data, in, JNI_ABORT);
    return fd;
}

JNIEXPORT jint JNICALL JNI_OnLoad(JavaVM *vm, void *reserved) {
    (void)vm; (void)reserved;
    return JNI_VERSION_1_6;
}
