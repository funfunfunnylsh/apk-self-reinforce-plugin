package com.selfprotect;

import android.app.Application;
import android.content.Context;
import android.content.pm.ApplicationInfo;
import android.os.Build;
import android.os.Process;
import android.util.Log;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileOutputStream;
import java.lang.reflect.Field;
import java.lang.reflect.Method;
import java.nio.ByteBuffer;
import java.util.ArrayList;
import java.util.List;
import java.util.zip.ZipEntry;
import java.util.zip.ZipInputStream;

import dalvik.system.DexClassLoader;
import dalvik.system.InMemoryDexClassLoader;

/**
 * 自研加固壳 Application（对应百度加固的 com.sagittarius.v6.StubApplication）。
 *
 * 两阶段接力（关键：framework 的 makeApplication 收尾会覆盖引用，必须在 onCreate 再修一次）：
 *  attachBaseContext():
 *    1. 读取 assets/selfprotect/config.txt 得到原 Application 全限定名
 *    2. 解密 assets/selfprotect/payload.dat -> payload.zip（内含原 classes*.dex）
 *    3. 以原 ClassLoader 为 parent 创建 DexClassLoader，并替换 LoadedApk.mClassLoader
 *    4. 反射实例化原 Application 并 attach（此时 framework 尚未完成 makeApplication，
 *       因此只做 mApplication 的初步设置，完整引用修正留给 onCreate）
 *  onCreate():
 *    5. framework 已完成 mInitialApplication/mAllApplications/setOuterContext 的赋值（都是壳实例），
 *       这里统一修正为真实 Application，然后调用真实 Application.onCreate()
 */
public class StubApplication extends Application {

    private static final String TAG = "SelfProtect";

    private static final String PAYLOAD_ASSET = "selfprotect/payload.dat";
    private static final String CONFIG_ASSET = "selfprotect/config.txt";
    private static final String WORK_DIR = "selfprotect";

    /**
     * 内存加载开关（v1.4.0 实测结论：保持 false 最稳）：
     *  - false：DexClassLoader 落盘（v1.1.x 真机验证过的路径，最稳）
     *  - true ：API26+ InMemoryDexClassLoader（零落盘，加载快 ~1.4s）
     *  v1.4.0 曾启用 InMemory 加速，但真实大包（extractNativeLibs=false，so 内嵌
     *  base.apk!）在 androidx.startup Provider 阶段 System.loadLibrary("mmkv") 失败崩溃。
     *  InMemoryDexClassLoader 的原生库解析对 base.apk!/lib 内嵌 so 不可靠，即使反射
     *  合并 nativeLibraryDirectories 也无法解决。故回退落盘路径（稳定，dex2oat ~6s）。
     */
    private static final boolean USE_IN_MEMORY_LOADER = false;

    private Application mRealApplication;
    private ArrayList<ActivityLifecycleCallbacks> mPendingCallbacks;

    @Override
    protected void attachBaseContext(Context base) {
        super.attachBaseContext(base);
        try {
            Log.i(TAG, "attachBaseContext enter, pkg=" + base.getPackageName());

            // ===== native 安全初始化（反调试 + 反模拟器 + 反 root，尽早执行）=====
            boolean nativeOk = ShellNative.load();
            if (nativeOk) {
                int sec = ShellNative.init(
                        ShellNative.FLAG_ANTI_DEBUG | ShellNative.FLAG_ANTI_EMULATOR | ShellNative.FLAG_ANTI_ROOT);
                if (sec != 0) {
                    Log.w(TAG, "native security triggered: code=" + sec);
                    Process.killProcess(Process.myPid());
                    return;
                }
                Log.i(TAG, "native security check passed");
            } else {
                // native 库不可用（理论不出现）：降级到 Java 层检测
                Log.w(TAG, "native lib unavailable, fallback to java checks");
            }

            // ===== Java 层安全校验：防重打包 + 反动态注入 + 载荷完整性 =====
            String hookInfo = detectDynamicHooks(base);
            if (hookInfo != null) {
                Log.w(TAG, "anti-hook triggered: " + hookInfo);
            }
            String sigInfo = verifySignature(base);
            if (sigInfo != null) {
                Log.w(TAG, "anti-tamper triggered: " + sigInfo);
            }
            // 合并读取：payload.dat 只读一次，先校验哈希再解密，避免重复 I/O（18.5MB）
            byte[] encrypted = ShellCrypto.readAll(base.getAssets().open(PAYLOAD_ASSET));
            String payloadInfo = verifyPayloadHash(base, encrypted);
            if (payloadInfo != null) {
                Log.w(TAG, "payload integrity triggered: " + payloadInfo);
            }
            if (hookInfo != null || sigInfo != null || payloadInfo != null) {
                Log.w(TAG, "security check failed -> kill process");
                Process.killProcess(Process.myPid());
                return;
            }

            // 预加载 assets 加密清单（业务可用 SecureAssets.open 透明解密）
            SecureAssets.init(base);

            bypassHiddenApi();

            String realAppName = readConfig(base);
            Log.i(TAG, "real application class: " + realAppName);

            // 解密 payload（native 内存解密，不落盘；复用已读的密文，不再二次读取）
            byte[] payloadZip = decryptPayloadInMemory(base, encrypted);
            Log.i(TAG, "payload.zip size=" + payloadZip.length);

            ClassLoader newLoader = installClassLoaderInMemory(base, payloadZip);
            Log.i(TAG, "class loader installed, parent="
                    + (newLoader.getParent() == null ? "null" : newLoader.getParent().getClass().getName()));

            if (realAppName != null && realAppName.length() > 0) {
                mRealApplication = createRealApplication(base, newLoader, realAppName);
                Log.i(TAG, "real application created: " + mRealApplication.getClass().getName());
            }
        } catch (Throwable t) {
            Log.e(TAG, "shell boot failed", t);
            throw new RuntimeException("[selfprotect] 壳启动失败", t);
        }
    }

    @Override
    public void onCreate() {
        super.onCreate();
        if (mRealApplication != null) {
            // framework 此时已把 mInitialApplication/mAllApplications/mOuterContext 全部指向壳实例，
            // 必须在这里统一修正为真实 Application（否则 ActivityThread.currentApplication()
            // 返回壳对象，SDK 强转真实 Application 会 ClassCastException）
            fixApplicationReferences(mRealApplication);
            Log.i(TAG, "references fixed -> " + mRealApplication.getClass().getName());
            mRealApplication.onCreate();
        }
    }

    @Override
    public void registerActivityLifecycleCallbacks(ActivityLifecycleCallbacks callback) {
        if (mRealApplication != null) {
            mRealApplication.registerActivityLifecycleCallbacks(callback);
        } else {
            // 真 Application 尚未接力完成前注册的回调先缓存（百度壳同款处理）
            if (mPendingCallbacks == null) {
                mPendingCallbacks = new ArrayList<ActivityLifecycleCallbacks>();
            }
            mPendingCallbacks.add(callback);
        }
    }

    // ---------------------------------------------------------------------

    // ---------------------------------------------------------------------
    // 安全校验（防重打包 + 基础反调试）

    /** 与打包侧 ApkReinforcer.SIG_MASK 同步的指纹掩码 */
    private static final byte[] SIG_MASK = {
            0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x18, 0x29, 0x3A, 0x4B, 0x5C,
            0x6D, 0x7E, (byte) 0x8F, (byte) 0x90, (byte) 0xA1, (byte) 0xB2, (byte) 0xC3,
            (byte) 0xD4, (byte) 0xE5, (byte) 0xF6, 0x07, 0x19, 0x2A, 0x3B, 0x4C, 0x5D,
            0x6E, 0x7F, (byte) 0x88, (byte) 0x99
    };

    /** 与打包侧 ApkReinforcer.PAYLOAD_MASK 同步的载荷哈希掩码 */
    private static final byte[] PAYLOAD_MASK = {
            0x5A, 0x6B, 0x7C, 0x1D, 0x2E, 0x3F, 0x40, 0x51, 0x62, 0x73, (byte) 0x84, 0x15,
            0x26, 0x37, 0x48, 0x59, 0x6A, 0x7B, (byte) 0x8C, 0x1E, 0x2F, 0x30, 0x41, 0x52,
            0x63, 0x74, 0x05, 0x16, 0x27, 0x38, 0x49, (byte) 0x5B
    };

    /**
     * 基础反调试检测。命中任意一项返回原因字符串，否则返回 null：
     *  - AndroidManifest debuggable=true（debug 包直接拒绝）
     *  - Debug.isDebuggerConnected / waitingForDebugger（调试器已附加）
     *  - /proc/self/status 的 TracerPid != 0（ptrace 附加，包括调试器与部分 hook 框架）
     */
    private static String detectDebugging(Context base) {
        try {
            if ((base.getApplicationInfo().flags & ApplicationInfo.FLAG_DEBUGGABLE) != 0) {
                return "debuggable=true";
            }
        } catch (Throwable ignored) {
        }
        try {
            if (android.os.Debug.isDebuggerConnected()) {
                return "debugger connected";
            }
        } catch (Throwable ignored) {
        }
        try {
            if (android.os.Debug.waitingForDebugger()) {
                return "waiting for debugger";
            }
        } catch (Throwable ignored) {
        }
        try {
            String status = readFile("/proc/self/status");
            int idx = status.indexOf("TracerPid:");
            if (idx >= 0) {
                String rest = status.substring(idx + 10).trim();
                int end = 0;
                while (end < rest.length() && Character.isDigit(rest.charAt(end))) {
                    end++;
                }
                if (end > 0) {
                    int pid = Integer.parseInt(rest.substring(0, end));
                    if (pid != 0) {
                        return "TracerPid=" + pid;
                    }
                }
            }
        } catch (Throwable ignored) {
        }
        return null;
    }

    /**
     * 防重打包：校验 APK 实际签名证书 SHA-256 是否与打包时预置指纹一致。
     * 指纹以 XOR 掩码形式存于 assets/selfprotect/expected_sig.txt（避免明文直改）。
     * 返回 null 表示通过；未预置指纹（打包时未签名）也视为通过。
     */
    private static String verifySignature(Context base) {
        try {
            byte[] masked = ShellCrypto.readAll(base.getAssets().open("selfprotect/expected_sig.txt"));
            if (masked.length == 0) {
                return null;
            }
            if (masked.length != SIG_MASK.length) {
                return "fingerprint length mismatch";
            }
            String expected = toHex(unmask(masked, SIG_MASK));
            String actual = currentSignatureSha256(base);
            if (actual == null || !expected.equalsIgnoreCase(actual)) {
                return "signature mismatch, expected=" + expected + ", actual=" + actual;
            }
            return null;
        } catch (Throwable t) {
            // 读取异常（如指纹文件被删）按失败处理
            return "signature check error: " + t.getMessage();
        }
    }

    /**
     * 载荷完整性校验：解密前对 assets/selfprotect/payload.dat 密文计算 SHA-256，
     * 与打包时预置（XOR 掩码）的哈希比对，防止 APK 内的加密载荷被整体替换。
     * 返回 null 表示通过；未预置哈希视为通过（encrypted 可为 null，此时按需读取）。
     */
    private static String verifyPayloadHash(Context base, byte[] encrypted) {
        try {
            if (encrypted == null) {
                encrypted = ShellCrypto.readAll(base.getAssets().open("selfprotect/payload.dat"));
            }
            byte[] masked = ShellCrypto.readAll(base.getAssets().open("selfprotect/payload_hash.txt"));
            if (masked.length == 0) {
                return null;
            }
            if (masked.length != PAYLOAD_MASK.length) {
                return "payload hash length mismatch";
            }
            byte[] expected = unmask(masked, PAYLOAD_MASK);
            byte[] actual = sha256Bytes(encrypted);
            if (!java.util.Arrays.equals(expected, actual)) {
                return "payload hash mismatch";
            }
            return null;
        } catch (Throwable t) {
            return "payload hash error: " + t.getMessage();
        }
    }

    /**
     * 反动态注入（Frida / Xposed / Substrate 基础检测）：
     *  - 扫描 /proc/self/maps 中的注入库特征
     *  - 探测已知 hook 框架类（部分框架会在进程内加载其类）
     * 返回 null 表示未发现，否则返回命中特征。
     */
    private static String detectDynamicHooks(Context base) {
        String[] hookLibs = {
                "frida", "gum-js-loop", "gadget", "linjector", "xposed", "de.robv.android.xposed",
                "substrate", "libsubstrate", "substrate-stub", "riru", "zygisk"
        };
        try {
            String maps = readFile("/proc/self/maps").toLowerCase();
            for (String lib : hookLibs) {
                if (maps.contains(lib)) {
                    return "hook lib: " + lib;
                }
            }
        } catch (Throwable ignored) {
        }
        try {
            for (String cls : new String[]{
                    "de.robv.android.xposed.XposedBridge",
                    "de.robv.android.xposed.XposedHelpers",
                    "com.saurik.substrate.MS"
            }) {
                try {
                    Class.forName(cls, false, base.getClassLoader());
                    return "hook class: " + cls;
                } catch (Throwable ignored) {
                }
            }
        } catch (Throwable ignored) {
        }
        return null;
    }

    private static byte[] unmask(byte[] masked, byte[] mask) {
        byte[] out = new byte[masked.length];
        for (int i = 0; i < masked.length; i++) {
            out[i] = (byte) (masked[i] ^ mask[i]);
        }
        return out;
    }

    /** 取 APK 签名证书 SHA-256（API 28+ 用 signingInfo，旧版用 GET_SIGNATURES） */
    private static String currentSignatureSha256(Context base) {
        try {
            android.content.pm.PackageInfo info;
            if (android.os.Build.VERSION.SDK_INT >= 28) {
                info = base.getPackageManager().getPackageInfo(
                        base.getPackageName(), android.content.pm.PackageManager.GET_SIGNING_CERTIFICATES);
                if (info.signingInfo != null && info.signingInfo.getApkContentsSigners() != null) {
                    android.content.pm.Signature[] sigs = info.signingInfo.getApkContentsSigners();
                    if (sigs.length > 0) {
                        return sha256(sigs[0].toByteArray());
                    }
                }
            } else {
                info = base.getPackageManager().getPackageInfo(
                        base.getPackageName(), android.content.pm.PackageManager.GET_SIGNATURES);
                if (info.signatures != null && info.signatures.length > 0) {
                    return sha256(info.signatures[0].toByteArray());
                }
            }
        } catch (Throwable ignored) {
        }
        return null;
    }

    private static String sha256(byte[] data) {
        try {
            java.security.MessageDigest md = java.security.MessageDigest.getInstance("SHA-256");
            return toHex(md.digest(data));
        } catch (Throwable t) {
            return null;
        }
    }

    private static byte[] sha256Bytes(byte[] data) {
        // native SHA-256 优先（避免 Java MessageDigest 被 hook 干扰）
        if (ShellNative.isLoaded()) {
            try {
                byte[] nativeHash = ShellNative.sha256(data);
                if (nativeHash != null && nativeHash.length == 32) {
                    return nativeHash;
                }
            } catch (Throwable ignored) {
            }
        }
        try {
            return java.security.MessageDigest.getInstance("SHA-256").digest(data);
        } catch (Throwable t) {
            return new byte[0];
        }
    }

    private static String toHex(byte[] bytes) {
        StringBuilder sb = new StringBuilder(bytes.length * 2);
        for (byte b : bytes) {
            sb.append(Character.forDigit((b >> 4) & 0xF, 16));
            sb.append(Character.forDigit(b & 0xF, 16));
        }
        return sb.toString();
    }

    private static String readFile(String path) {
        try {
            java.io.FileInputStream fis = new java.io.FileInputStream(path);
            byte[] buf = new byte[fis.available() > 8192 ? 8192 : Math.max(fis.available(), 1)];
            int n = fis.read(buf);
            fis.close();
            return n > 0 ? new String(buf, 0, n, "UTF-8") : "";
        } catch (Throwable t) {
            return "";
        }
    }

    private static String readConfig(Context base) throws Exception {
        return new String(ShellCrypto.readAll(base.getAssets().open(CONFIG_ASSET)), "UTF-8").trim();
    }

    /**
     * native 内存解密 payload.dat -> zip 字节（不落盘）。
     * native 失败时回退 Java 解密（兼容旧包/密钥不一致场景，便于诊断）。
     */
    private static byte[] decryptPayloadInMemory(Context base, byte[] encrypted) throws Exception {
        if (encrypted == null) {
            encrypted = ShellCrypto.readAll(base.getAssets().open(PAYLOAD_ASSET));
        }
        if (ShellNative.isLoaded()) {
            byte[] plain = ShellNative.decryptPayload(encrypted);
            if (plain != null) {
                return plain;
            }
            Log.w(TAG, "native decrypt failed, fallback to java");
        }
        return ShellCrypto.decrypt(encrypted);
    }

    /**
     * 解开 payload zip 中的全部 classes*.dex，返回 dexIndex -> 字节。
     * dexIndex 约定：classes.dex=0, classes2.dex=2, classesN.dex=N（与打包侧 DexMethodExtractor 一致）。
     */
    private static java.util.LinkedHashMap<Integer, byte[]> readDexEntries(byte[] zipBytes) throws Exception {
        java.util.LinkedHashMap<Integer, byte[]> map = new java.util.LinkedHashMap<Integer, byte[]>();
        ZipInputStream zis = new ZipInputStream(new ByteArrayInputStream(zipBytes));
        ZipEntry entry;
        while ((entry = zis.getNextEntry()) != null) {
            String name = entry.getName();
            if (!entry.isDirectory() && name.matches("classes\\d*\\.dex")) {
                ByteArrayOutputStream bos = new ByteArrayOutputStream();
                byte[] buf = new byte[8192];
                int n;
                while ((n = zis.read(buf)) != -1) {
                    bos.write(buf, 0, n);
                }
                map.put(dexIndex(name), bos.toByteArray());
            }
            zis.closeEntry();
        }
        zis.close();
        return map;
    }

    /** dexIndex 升序的 dex 字节数组（classes.dex, classes2.dex, ...） */
    private static List<byte[]> orderedDexList(java.util.Map<Integer, byte[]> dexMap) {
        List<Integer> keys = new ArrayList<Integer>(dexMap.keySet());
        java.util.Collections.sort(keys);
        List<byte[]> out = new ArrayList<byte[]>(keys.size());
        for (Integer k : keys) {
            out.add(dexMap.get(k));
        }
        return out;
    }

    private static ByteBuffer[] toDirectBuffers(List<byte[]> dexes) {
        ByteBuffer[] bufs = new ByteBuffer[dexes.size()];
        for (int i = 0; i < dexes.size(); i++) {
            byte[] dex = dexes.get(i);
            ByteBuffer bb = ByteBuffer.allocateDirect(dex.length);
            bb.put(dex);
            bb.rewind();
            bufs[i] = bb;
        }
        return bufs;
    }

    /** dex 重打成 zip 字节（memfd 路径使用） */
    private static byte[] toZipBytes(java.util.Map<Integer, byte[]> dexMap) throws Exception {
        ByteArrayOutputStream bos = new ByteArrayOutputStream();
        java.util.zip.ZipOutputStream zos = new java.util.zip.ZipOutputStream(bos);
        List<Integer> keys = new ArrayList<Integer>(dexMap.keySet());
        java.util.Collections.sort(keys);
        for (Integer idx : keys) {
            String name = idx == 0 ? "classes.dex" : "classes" + idx + ".dex";
            zos.putNextEntry(new ZipEntry(name));
            zos.write(dexMap.get(idx));
            zos.closeEntry();
        }
        zos.close();
        return bos.toByteArray();
    }

    /** 把 dex 重新打成 zip（方法回填后落盘路径使用） */
    private static void writePayloadZip(File target, java.util.Map<Integer, byte[]> dexMap) throws Exception {
        FileOutputStream fos = new FileOutputStream(target);
        try {
            fos.write(toZipBytes(dexMap));
        } finally {
            fos.close();
        }
    }

    /**
     * 关键方法还原（与打包侧 DexMethodExtractor 对应）：
     * 读取 assets/selfprotect/methods.dat，解密后按 (dexIndex, codeOff) 把原始 code_item
     * 回填进内存中的 dex 字节 —— 真实方法体只存在于内存，静态反编译只能看到桩。
     *
     * @return 还原的方法数；无 methods.dat（未启用抽取）返回 0
     */
    private static int restoreExtractedMethods(Context base, java.util.Map<Integer, byte[]> dexMap) throws Exception {
        byte[] enc;
        try {
            enc = ShellCrypto.readAll(base.getAssets().open("selfprotect/methods.dat"));
        } catch (Throwable t) {
            return 0; // 未启用方法抽取
        }
        if (enc.length == 0) {
            return 0;
        }
        byte[] blob = null;
        if (ShellNative.isLoaded()) {
            blob = ShellNative.decryptPayload(enc);
        }
        if (blob == null) {
            blob = ShellCrypto.decrypt(enc);
        }
        // 格式：'S','P','M','E' | u32 version | u32 count | [u16 dexIndex|u32 codeOff|u32 len|bytes]（小端）
        if (blob.length < 12 || blob[0] != 'S' || blob[1] != 'P' || blob[2] != 'M' || blob[3] != 'E') {
            throw new IllegalStateException("methods.dat magic 不匹配（可能被篡改）");
        }
        long count = u32le(blob, 8);
        int pos = 12;
        int restored = 0;
        for (long i = 0; i < count; i++) {
            int dexIndex = u16le(blob, pos);
            pos += 2;
            long codeOff = u32le(blob, pos);
            pos += 4;
            long len = u32le(blob, pos);
            pos += 4;
            byte[] dex = dexMap.get(dexIndex);
            if (dex == null || codeOff < 0 || codeOff + len > dex.length || len < 0 || pos + len > blob.length) {
                throw new IllegalStateException("methods.dat 记录越界（dexIndex=" + dexIndex
                        + ", codeOff=" + codeOff + ", len=" + len + "）");
            }
            System.arraycopy(blob, pos, dex, (int) codeOff, (int) len);
            pos += (int) len;
            restored++;
        }
        return restored;
    }

    private static int u16le(byte[] b, int off) {
        return (b[off] & 0xFF) | ((b[off + 1] & 0xFF) << 8);
    }

    private static long u32le(byte[] b, int off) {
        return ((long) b[off] & 0xFF) | (((long) b[off + 1] & 0xFF) << 8)
                | (((long) b[off + 2] & 0xFF) << 16) | (((long) b[off + 3] & 0xFF) << 24);
    }

    private static int dexIndex(String name) {
        String n = name.substring(0, name.length() - 4).replace("classes", "");
        return n.isEmpty() ? 0 : Integer.parseInt(n);
    }

    private static void writeU32(byte[] buf, int off, long v) {
        buf[off] = (byte) (v & 0xFF);
        buf[off + 1] = (byte) ((v >>> 8) & 0xFF);
        buf[off + 2] = (byte) ((v >>> 16) & 0xFF);
        buf[off + 3] = (byte) ((v >>> 24) & 0xFF);
    }

    /**
     * 修改 dex 字节后重算 header 中的 SHA-1 签名（offset 12-31）与 adler32 校验和（offset 8-11）。
     * 与打包侧 DexMethodExtractor.fixDexHeader 同算法。
     * restoreExtractedMethods 回填原始 code_item 后必须调用，否则 ART 校验和不匹配
     * 会静默拒绝加载该 dex -> dexElements 为空 -> ClassNotFoundException。
     */
    private static void fixDexChecksums(byte[] dex) {
        try {
            java.security.MessageDigest md = java.security.MessageDigest.getInstance("SHA-1");
            byte[] sha = md.digest(java.util.Arrays.copyOfRange(dex, 32, dex.length));
            System.arraycopy(sha, 0, dex, 12, 20);
            java.util.zip.Adler32 adler = new java.util.zip.Adler32();
            adler.update(dex, 12, dex.length - 12);
            writeU32(dex, 8, adler.getValue());
        } catch (Throwable t) {
            Log.w(TAG, "fixDexChecksums failed: " + t);
        }
    }

    /**
     * 创建内存 ClassLoader 并替换 LoadedApk.mClassLoader，parent 设为原 ClassLoader：
     *  0. 解开 payload zip；若存在 methods.dat 则先把抽取的方法体回填进内存 dex（真实字节码不落 APK）
     *  - API 26+：优先 InMemoryDexClassLoader（零落盘）；构造失败回退 DexClassLoader 落盘临时文件
     *  - API < 26：native memfd_create + DexClassLoader("/proc/self/fd/N")（匿名内存，不落盘）
     * 替换后同步 mBoundApplication.info（防 Activity 侧 LoadedApk 与 context 侧不同实例）。
     */
    private static ClassLoader installClassLoaderInMemory(Context base, byte[] zipBytes) throws Exception {
        ClassLoader oldLoader = base.getClassLoader();
        ClassLoader newLoader = null;

        // 解开 payload，并按需回填被抽取的方法体（methods.dat）
        java.util.LinkedHashMap<Integer, byte[]> dexMap = readDexEntries(zipBytes);
        if (dexMap.isEmpty()) {
            throw new IllegalStateException("payload 内未找到 classes*.dex");
        }
        int restored = restoreExtractedMethods(base, dexMap);
        if (restored > 0) {
            Log.i(TAG, "extracted methods restored in memory: " + restored);
            // 回填原始 code_item 后 dex 字节已变，必须重算 SHA-1/adler32，
            // 否则 DexClassLoader 加载时 ART 校验和不匹配会静默拒绝 dex -> ClassNotFoundException
            for (byte[] dex : dexMap.values()) {
                fixDexChecksums(dex);
            }
        }

        if (USE_IN_MEMORY_LOADER && Build.VERSION.SDK_INT >= 26) {
            try {
                ByteBuffer[] dexs = toDirectBuffers(orderedDexList(dexMap));
                newLoader = new InMemoryDexClassLoader(dexs, oldLoader);
                Log.i(TAG, "InMemoryDexClassLoader created, dex count=" + dexs.length);
                // InMemory 的原生库路径独立于宿主，需合并宿主 nativeLibraryDirectories，
                // 否则 System.loadLibrary（如 MMKV）找不到 so 而崩溃。
                patchNativeLibDirectories(newLoader, oldLoader);
            } catch (Throwable t) {
                newLoader = null;
                Log.w(TAG, "InMemoryDexClassLoader failed: " + t);
            }
        }

        if (newLoader == null) {
            // 回退/默认：memfd（API<26 或 native 可用时，不落盘）
            if (USE_IN_MEMORY_LOADER && ShellNative.isLoaded()) {
                // 回填后的 dex 可能与原 payload 不同，必须用重打包后的字节
                int fd = ShellNative.createMemfd("payload.zip", restored > 0 ? toZipBytes(dexMap) : zipBytes);
                if (fd >= 0) {
                    try {
                        File odexDir = new File(base.getFilesDir(), WORK_DIR + "/odex");
                        if (!odexDir.exists()) {
                            odexDir.mkdirs();
                        }
                        newLoader = new DexClassLoader(
                                "/proc/self/fd/" + fd,
                                odexDir.getAbsolutePath(),
                                buildLibrarySearchPath(base, oldLoader),
                                oldLoader);
                        Log.i(TAG, "memfd DexClassLoader created, fd=" + fd);
                    } catch (Throwable t) {
                        Log.w(TAG, "memfd DexClassLoader failed: " + t);
                        newLoader = null;
                    }
                }
            }
            // 默认/兜底：落盘临时文件（v1.1.x 验证过的稳定路径）
            if (newLoader == null) {
                File dir = new File(base.getFilesDir(), WORK_DIR);
                if (!dir.exists() && !dir.mkdirs()) {
                    throw new IllegalStateException("无法创建工作目录: " + dir);
                }
                File zip = new File(dir, "payload.zip");
                writePayloadZip(zip, dexMap);
                File odexDir = new File(dir, "odex");
                if (!odexDir.exists()) {
                    odexDir.mkdirs();
                }
                newLoader = new DexClassLoader(
                        zip.getAbsolutePath(),
                        odexDir.getAbsolutePath(),
                        buildLibrarySearchPath(base, oldLoader),
                        oldLoader);
                Log.i(TAG, "DexClassLoader (payload 落盘): " + zip);
            }
        }

        // 替换 LoadedApk.mClassLoader（context 侧）
        Object loadedApk = findField(base, "mPackageInfo").get(base);
        if (loadedApk == null) {
            throw new IllegalStateException("LoadedApk 为空，无法替换 ClassLoader");
        }
        Field classLoaderField = findField(loadedApk, "mClassLoader");
        classLoaderField.set(loadedApk, newLoader);
        Log.i(TAG, "LoadedApk.mClassLoader replaced -> " + newLoader.getClass().getName());

        // 双保险：同步 ActivityThread.mBoundApplication.info（若与 context 侧 LoadedApk 不同实例）
        try {
            Class<?> atClass = Class.forName("android.app.ActivityThread");
            Method current = atClass.getDeclaredMethod("currentActivityThread");
            current.setAccessible(true);
            Object at = current.invoke(null);
            if (at != null) {
                Object bound = findField(at, "mBoundApplication").get(at);
                if (bound != null) {
                    Object boundInfo = findField(bound, "info").get(bound);
                    if (boundInfo != null && boundInfo != loadedApk) {
                        findField(boundInfo, "mClassLoader").set(boundInfo, newLoader);
                        Log.w(TAG, "mBoundApplication.info.mClassLoader also replaced (different LoadedApk)");
                    }
                }
            }
        } catch (Throwable ignored) {
        }

        // 自检：反射读取 newLoader 的 dexElements 数量，确认 payload dex 已挂载
        try {
            Object pathList = findField(newLoader, "pathList").get(newLoader);
            Object elements = findField(pathList, "dexElements").get(pathList);
            int count = (elements instanceof Object[]) ? ((Object[]) elements).length : -1;
            Log.i(TAG, "newLoader dexElements count=" + count);
        } catch (Throwable t) {
            Log.w(TAG, "newLoader self-check failed: " + t);
        }
        return newLoader;
    }

    /**
     * 构建 native 库搜索路径。
     * 必须复用原 ClassLoader 的 nativeLibraryDirectories —— 当 App 使用
     * extractNativeLibs=false 时，so 直接从 base.apk!/lib/<abi> 映射加载，
     * 只传 ApplicationInfo.nativeLibraryDir 会导致 System.loadLibrary 找不到 so。
     */
    private static String buildLibrarySearchPath(Context base, ClassLoader oldLoader) {
        try {
            Object pathList = findField(oldLoader, "pathList").get(oldLoader);
            StringBuilder sb = new StringBuilder();
            appendPaths(sb, findField(pathList, "nativeLibraryDirectories").get(pathList));
            appendPaths(sb, findField(pathList, "systemNativeLibraryDirectories").get(pathList));
            if (sb.length() > 0) {
                return sb.toString();
            }
        } catch (Throwable ignored) {
        }
        // 兜底：nativeLibraryDir + APK 内嵌 so 路径
        ApplicationInfo info = base.getApplicationInfo();
        return info.nativeLibraryDir + File.pathSeparator
                + info.sourceDir + "!/lib/" + android.os.Build.SUPPORTED_ABIS[0];
    }

    /**
     * InMemoryDexClassLoader 的原生库路径独立于宿主 ClassLoader，导致 System.loadLibrary
     * （如 MMKV）找不到 so。这里把宿主 pathList 的 nativeLibraryDirectories 合并进内存 loader，
     * 保持原生库可加载。失败静默（memfd/落盘路径自带 librarySearchPath，无需此修补）。
     */
    private static void patchNativeLibDirectories(ClassLoader newLoader, ClassLoader oldLoader) {
        try {
            if (newLoader == null || oldLoader == null) {
                return;
            }
            Object newPathList = findField(newLoader, "pathList").get(newLoader);
            Object oldPathList = findField(oldLoader, "pathList").get(oldLoader);
            java.util.List<?> oldDirs = (java.util.List<?>) findField(oldPathList, "nativeLibraryDirectories").get(oldPathList);
            if (oldDirs == null || oldDirs.isEmpty()) {
                return;
            }
            // 合并：新 loader 已有的 + 宿主的（去重）
            java.util.LinkedHashSet<Object> merged = new java.util.LinkedHashSet<>();
            Object newDirs = findField(newPathList, "nativeLibraryDirectories").get(newPathList);
            if (newDirs instanceof java.util.List) {
                merged.addAll((java.util.List<?>) newDirs);
            }
            merged.addAll(oldDirs);
            findField(newPathList, "nativeLibraryDirectories").set(newPathList, new java.util.ArrayList<>(merged));
            Log.i(TAG, "nativeLibraryDirectories patched for InMemory loader, dirs=" + merged.size());
        } catch (Throwable t) {
            Log.w(TAG, "patchNativeLibDirectories failed: " + t);
        }
    }

    private static void appendPaths(StringBuilder sb, Object dirs) {
        if (!(dirs instanceof java.util.List)) {
            return;
        }
        for (Object dir : (java.util.List<?>) dirs) {
            if (sb.length() > 0) {
                sb.append(File.pathSeparator);
            }
            sb.append(dir instanceof File ? ((File) dir).getAbsolutePath() : String.valueOf(dir));
        }
    }

    /**
     * 实例化原 Application 并 attach。注意：这里不做 LoadedApk/ActivityThread/ContextImpl
     * 的引用修正（framework 的 makeApplication 收尾会覆盖），只保证实例可用。
     */
    private Application createRealApplication(Context base, ClassLoader loader, String className) throws Exception {
        Class<?> appClass = Class.forName(className, true, loader);
        Application real = (Application) appClass.newInstance();

        // attach：触发真实 Application 的 attachBaseContext（此时 mBase 已就绪）
        Method attach = Application.class.getDeclaredMethod("attach", Context.class);
        attach.setAccessible(true);
        attach.invoke(real, base);

        // 初步把 LoadedApk.mApplication 指向 real：
        // 虽然会被 makeApplication 覆盖回壳实例，但能让 ContentProvider 阶段
        // context.getApplicationContext() 拿到真实 Application 而非 null
        try {
            Object loadedApk = findField(base, "mPackageInfo").get(base);
            if (loadedApk != null) {
                findField(loadedApk, "mApplication").set(loadedApk, real);
            }
        } catch (Throwable ignored) {
        }

        // 回放缓存的生命周期回调
        if (mPendingCallbacks != null) {
            for (ActivityLifecycleCallbacks cb : mPendingCallbacks) {
                real.registerActivityLifecycleCallbacks(cb);
            }
            mPendingCallbacks = null;
        }
        return real;
    }

    /**
     * 最终引用修正（必须在 onCreate 中执行，此时 framework 全部赋值已完成）：
     *  LoadedApk.mApplication / ActivityThread.mInitialApplication / mAllApplications / ContextImpl.mOuterContext
     */
    private void fixApplicationReferences(Application real) {
        Context base = getBaseContext();
        if (base == null) {
            return;
        }
        try {
            Object loadedApk = findField(base, "mPackageInfo").get(base);
            if (loadedApk != null) {
                findField(loadedApk, "mApplication").set(loadedApk, real);
            }
        } catch (Throwable ignored) {
        }
        try {
            Class<?> atClass = Class.forName("android.app.ActivityThread");
            Method current = atClass.getDeclaredMethod("currentActivityThread");
            current.setAccessible(true);
            Object activityThread = current.invoke(null);
            if (activityThread != null) {
                try {
                    findField(activityThread, "mInitialApplication").set(activityThread, real);
                } catch (Throwable ignored) {
                }
                try {
                    Object all = findField(activityThread, "mAllApplications").get(activityThread);
                    if (all instanceof ArrayList) {
                        @SuppressWarnings("unchecked")
                        ArrayList<Object> list = (ArrayList<Object>) all;
                        list.remove(this);
                        if (!list.contains(real)) {
                            list.add(real);
                        }
                    }
                } catch (Throwable ignored) {
                }
            }
        } catch (Throwable ignored) {
        }
        try {
            findField(base, "mOuterContext").set(base, real);
        } catch (Throwable ignored) {
        }
    }

    /** API 28+ 绕过 hidden API 反射限制（尽力而为；Android 10+ 反射调用本身可能被拦，不致命） */
    private static void bypassHiddenApi() {
        try {
            Class<?> vmRuntime = Class.forName("dalvik.system.VMRuntime");
            Method getRuntime = vmRuntime.getDeclaredMethod("getRuntime");
            getRuntime.setAccessible(true);
            Object runtime = getRuntime.invoke(null);
            Method setExemptions = vmRuntime.getDeclaredMethod("setHiddenApiExemptions", String[].class);
            setExemptions.setAccessible(true);
            setExemptions.invoke(runtime, new Object[]{new String[]{"L"}});
            Log.i(TAG, "hidden api exemptions applied");
        } catch (Throwable t) {
            // Android 10+ 上 setHiddenApiExemptions 对 targetSdk>=29 属黑名单，反射调用可能失败；
            // 我们的目标字段（mPackageInfo/mClassLoader/mApplication 等）多为 greylist，可不豁免。
            Log.w(TAG, "hidden api exemption failed: " + t.getMessage());
        }
    }

    private static Field findField(Object target, String name) throws NoSuchFieldException {
        Class<?> cls = target instanceof Class ? (Class<?>) target : target.getClass();
        while (cls != null) {
            try {
                Field f = cls.getDeclaredField(name);
                f.setAccessible(true);
                return f;
            } catch (NoSuchFieldException e) {
                cls = cls.getSuperclass();
            }
        }
        throw new NoSuchFieldException(name);
    }
}
