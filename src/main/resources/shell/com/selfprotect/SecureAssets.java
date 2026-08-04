package com.selfprotect;

import android.content.Context;
import android.util.Log;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.util.HashMap;
import java.util.Map;

/**
 * assets 资源透明解密（配合打包侧 assets 加密）。
 *
 * 打包侧把配置白名单内的 assets 文件加密为 assets/enc/<path>，
 * 并生成清单 assets/selfprotect/assets_map.txt（每行：加密路径|原始路径）。
 *
 * 业务侧用法：
 *    InputStream in = SecureAssets.open(context, "private/data.bin");
 * 未加密的文件原样走 AssetManager，加密文件首次访问时解密到
 * filesDir/selfprotect/assets/<path> 后返回文件流。
 */
public final class SecureAssets {

    private static final String TAG = "SelfProtect";
    private static final String ASSETS_MAP = "selfprotect/assets_map.txt";
    private static final String CACHE_ROOT = "selfprotect/assets";

    private static volatile Map<String, String> sEncMap; // 原始路径 -> 加密路径

    private SecureAssets() {
    }

    /** 预加载加密清单（壳 attachBaseContext 时调用） */
    public static synchronized void init(Context context) {
        if (sEncMap != null) {
            return;
        }
        Map<String, String> map = new HashMap<String, String>();
        try {
            String content = new String(ShellCrypto.readAll(context.getAssets().open(ASSETS_MAP)), "UTF-8");
            for (String line : content.split("\n")) {
                line = line.trim();
                if (line.length() == 0) {
                    continue;
                }
                int sep = line.indexOf('|');
                if (sep > 0) {
                    map.put(line.substring(sep + 1), line.substring(0, sep));
                }
            }
        } catch (Throwable t) {
            // 无清单 = 未启用 assets 加密，保持空表即可
        }
        sEncMap = map;
        Log.i(TAG, "secure assets entries: " + map.size());
    }

    /**
     * 打开资源：优先透明解密，未加密直接走 AssetManager。
     * @param assetPath 原始 assets 路径，如 "private/data.bin"
     */
    public static InputStream open(Context context, String assetPath) throws IOException {
        Map<String, String> map = sEncMap;
        if (map == null) {
            init(context);
            map = sEncMap;
        }
        String encPath = map != null ? map.get(assetPath) : null;
        if (encPath == null) {
            // 未加密资源：原样读取
            return context.getAssets().open(assetPath);
        }
        File cache = decryptToCache(context, encPath, assetPath);
        return new FileInputStream(cache);
    }

    /** 解密加密资源到缓存目录（幂等：已存在直接返回） */
    private static File decryptToCache(Context context, String encPath, String origPath) throws IOException {
        File dir = new File(context.getFilesDir(), CACHE_ROOT);
        if (!dir.exists() && !dir.mkdirs()) {
            throw new IOException("无法创建缓存目录: " + dir);
        }
        File cache = new File(dir, origPath);
        if (cache.exists() && cache.length() > 0) {
            return cache;
        }
        cache.getParentFile().mkdirs();
        try {
            byte[] encrypted = ShellCrypto.readAll(context.getAssets().open(encPath));
            byte[] plain = ShellCrypto.decrypt(encrypted);
            File tmp = new File(dir, origPath + ".tmp");
            FileOutputStream fos = new FileOutputStream(tmp);
            try {
                fos.write(plain);
            } finally {
                fos.close();
            }
            if (!tmp.renameTo(cache)) {
                cache.delete();
                if (!tmp.renameTo(cache)) {
                    throw new IOException("缓存写入失败: " + cache);
                }
            }
            return cache;
        } catch (IOException e) {
            throw e;
        } catch (Throwable t) {
            throw new IOException("解密资源失败: " + encPath, t);
        }
    }
}
