package com.selfprotect;

import android.util.Log;

/**
 * 壳 native 层绑定（libselfprotect.so，由加固流水线注入 APK 的 lib/<abi>/）。
 *
 * 所有敏感逻辑（密钥、解密、反调试、环境检测）都在 native，Java 层只做绑定与结果处理。
 */
final class ShellNative {

    private static final String TAG = "SelfProtect";

    static final int FLAG_ANTI_DEBUG = 1;
    static final int FLAG_ANTI_EMULATOR = 2;
    static final int FLAG_ANTI_ROOT = 4;

    private static volatile boolean loaded = false;

    private ShellNative() {
    }

    /** 加载 libselfprotect.so；失败返回 false（调用方降级到 Java 层检测） */
    static synchronized boolean load() {
        if (loaded) {
            return true;
        }
        try {
            System.loadLibrary("selfprotect");
            loaded = true;
            return true;
        } catch (Throwable t) {
            Log.w(TAG, "load libselfprotect failed: " + t.getMessage());
            return false;
        }
    }

    static boolean isLoaded() {
        return loaded;
    }

    /**
     * 安全初始化（在 attachBaseContext 尽早调用）。
     *
     * @param flags FLAG_ANTI_DEBUG | FLAG_ANTI_EMULATOR | FLAG_ANTI_ROOT
     * @return 0 通过；非 0 命中位组合（1=反调试 2=模拟器 4=root）
     */
    static native int init(int flags);

    /**
     * AES-CBC 解密 payload（密钥在 native）。
     *
     * @param encrypted [16 字节 IV][密文]
     * @return 明文 zip 字节；失败 null
     */
    static native byte[] decryptPayload(byte[] encrypted);

    /** SHA-256，返回 32 字节；失败 null */
    static native byte[] sha256(byte[] data);

    /**
     * memfd_create 匿名内存文件并写入数据（API<26 时载荷不落盘用）。
     *
     * @return fd；失败 -1
     */
    static native int createMemfd(String name, byte[] data);
}
