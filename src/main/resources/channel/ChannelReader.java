package com.selfprotect.reinforce;

import android.content.Context;
import java.io.File;
import java.io.RandomAccessFile;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;

/**
 * 多渠道读取（与 walle 方案兼容）。
 *
 * 渠道信息由加固插件写入 APK v2 Signing Block 的 0x71777777 条目，
 * 运行时读取自身 APK 文件即可获得，无需网络、无需额外依赖。
 *
 * 用法：
 *   String channel = ChannelReader.getChannel(this);   // Context
 *   String channel = ChannelReader.getChannel(apkPath); // 纯 Java，任意 JVM 可用
 * 未写入渠道时返回 null。
 */
public final class ChannelReader {

    private static final byte[] MAGIC = "APK Sig Block 42".getBytes(StandardCharsets.US_ASCII);
    private static final int CHANNEL_ID = 0x71777777;

    private ChannelReader() {
    }

    /** 从当前 App 的 APK 中读取渠道（无渠道返回 null） */
    public static String getChannel(Context context) {
        if (context == null || context.getApplicationInfo() == null) {
            return null;
        }
        return getChannel(context.getApplicationInfo().sourceDir);
    }

    /** 从指定 APK 文件中读取渠道（纯 Java，无 Android 依赖的解析路径） */
    public static String getChannel(String apkPath) {
        if (apkPath == null) {
            return null;
        }
        File f = new File(apkPath);
        if (!f.exists() || !f.isFile()) {
            return null;
        }
        try {
            RandomAccessFile raf = new RandomAccessFile(f, "r");
            try {
                return readChannel(raf, f.length());
            } finally {
                raf.close();
            }
        } catch (Throwable t) {
            return null;
        }
    }

    /**
     * Signing Block 结构（AOSP / walle 标准）：
     *   [size u64][pairs...][size u64][magic "APK Sig Block 42"]
     *   size 字段 = 从该字段之后到 magic 末尾的总长（不含 size 字段自身 8 字节）
     *   pair = [size u64][id u32][value][padding 到 4 对齐]，pair size 同样不含自身 8 字节
     *   块起点 = cdOffset - size - 8
     */
    private static String readChannel(RandomAccessFile raf, long fileLen) throws Exception {
        long eocdPos = findEocd(raf, fileLen);
        if (eocdPos < 0) {
            return null;
        }
        long cdOffset = readUInt(raf, eocdPos + 16);
        if (cdOffset < 24 || cdOffset > fileLen) {
            return null;
        }
        // magic 校验
        raf.seek(cdOffset - 16);
        byte[] magic = new byte[16];
        raf.readFully(magic);
        if (!Arrays.equals(MAGIC, magic)) {
            return null;
        }
        long blockSize = readULong(raf, cdOffset - 24);
        long blockStart = cdOffset - blockSize - 8;
        long pairsEnd = cdOffset - 24;
        if (blockStart < 0 || blockStart + 8 > pairsEnd) {
            return null;
        }
        long pos = blockStart + 8;
        while (pos + 12 <= pairsEnd) {
            long pairSize = readULong(raf, pos); // 不含自身 8 字节；= id(4) + value + padding
            int id = (int) readUInt(raf, pos + 8);
            if (id == CHANNEL_ID) {
                int len = (int) pairSize - 4; // value 区 = pairSize - id 的 4 字节
                byte[] buf = new byte[len];
                raf.seek(pos + 12);
                raf.readFully(buf);
                int end = buf.length;
                while (end > 0 && buf[end - 1] == 0) {
                    end--; // 去掉 4 字节对齐的 \0 padding
                }
                return new String(buf, 0, end, StandardCharsets.UTF_8);
            }
            pos += 8 + pairSize;
        }
        return null;
    }

    /** 从文件尾部定位 EOCD（PK\x05\x06），校验 comment 长度，返回其偏移；找不到返回 -1 */
    private static long findEocd(RandomAccessFile raf, long fileLen) throws Exception {
        long start = Math.max(0, fileLen - (22 + 65535)); // EOCD 最大 22 + comment 65535
        int bufLen = (int) (fileLen - start);
        byte[] buf = new byte[bufLen];
        raf.seek(start);
        raf.readFully(buf);
        for (int i = bufLen - 22; i >= 0; i--) {
            if ((buf[i] & 0xFF) == 0x50 && (buf[i + 1] & 0xFF) == 0x4B
                    && (buf[i + 2] & 0xFF) == 0x05 && (buf[i + 3] & 0xFF) == 0x06) {
                int commentLen = (buf[i + 20] & 0xFF) | ((buf[i + 21] & 0xFF) << 8);
                if (i + 22 + commentLen == bufLen) {
                    return start + i;
                }
            }
        }
        return -1;
    }

    private static long readUInt(RandomAccessFile raf, long pos) throws Exception {
        raf.seek(pos);
        long b0 = raf.read() & 0xFF;
        long b1 = raf.read() & 0xFF;
        long b2 = raf.read() & 0xFF;
        long b3 = raf.read() & 0xFF;
        return b0 | (b1 << 8) | (b2 << 16) | (b3 << 24);
    }

    private static long readULong(RandomAccessFile raf, long pos) throws Exception {
        raf.seek(pos);
        long v = 0;
        for (int i = 0; i < 8; i++) {
            v |= ((long) (raf.read() & 0xFF)) << (8 * i);
        }
        return v;
    }
}
