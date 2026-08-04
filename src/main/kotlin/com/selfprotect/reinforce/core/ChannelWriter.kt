package com.selfprotect.reinforce.core

import java.io.ByteArrayOutputStream
import java.nio.ByteBuffer
import java.nio.ByteOrder
import java.nio.charset.Charset

/**
 * 多渠道打包器（复刻 walle 方案：写入 APK Signing Block，无需重签名）。
 *
 * 原理：
 *  - v2/v3 签名只覆盖「签名块之前」的内容，签名块之后的 Central Directory / EOCD
 *    不受签名保护 —— 因此可以直接在签名块内插入自定义 pair（ID 0x71777777），
 *    再修正 EOCD 中的 Central Directory 偏移即可，**不需要重签名**，秒级完成。
 *  - 无 v2 签名块（v1-only 或未签名）的 APK 同样支持：在 CD 之前新建签名块。
 *
 * 渠道 value 格式：渠道名 UTF-8 字节（自定义，与 walle protobuf 不互读）。
 */
object ChannelWriter {

    const val WALLE_CHANNEL_ID = 0x71777777
    private val MAGIC = "APK Sig Block 42".toByteArray(Charsets.US_ASCII)
    private val EOCD_SIG = byteArrayOf(0x50, 0x4B, 0x05, 0x06)

    class ChannelException(msg: String) : RuntimeException(msg)

    /**
     * 写入渠道并返回新 APK 字节。
     * @param apk     原 APK 字节（可为未签名 / v1 / v2 签名）
     * @param channel 渠道名（任意字符串，建议简短 ASCII）
     */
    fun writeChannel(apk: ByteArray, channel: String): ByteArray {
        val (eocdPos, cdOffset) = locateEocd(apk)
        val oldBlock = findSigningBlock(apk, cdOffset)

        val newBlock = if (oldBlock != null) {
            replacePair(oldBlock, WALLE_CHANNEL_ID, channel.toByteArray(Charsets.UTF_8))
        } else {
            buildNewBlock(WALLE_CHANNEL_ID, channel.toByteArray(Charsets.UTF_8))
        }

        val oldBlockLen = oldBlock?.size ?: 0
        val delta = newBlock.size - oldBlockLen
        val blockStart = cdOffset - oldBlockLen

        val out = ByteArrayOutputStream(apk.size + delta)
        out.write(apk, 0, blockStart)
        out.write(newBlock)
        out.write(apk, blockStart + oldBlockLen, apk.size - blockStart - oldBlockLen)
        val result = out.toByteArray()

        // 修正 EOCD：Central Directory 偏移 += delta（EOCD 位置仍在文件末尾，不变）
        val newEocdPos = result.size - (apk.size - eocdPos)
        ByteBuffer.wrap(result).order(ByteOrder.LITTLE_ENDIAN)
            .putInt(newEocdPos + 16, cdOffset + delta)
        return result
    }

    /** 读取渠道（无渠道返回 null） */
    fun readChannel(apk: ByteArray): String? {
        val (_, cdOffset) = locateEocd(apk)
        val block = findSigningBlock(apk, cdOffset) ?: return null
        val value = findPair(block, WALLE_CHANNEL_ID) ?: return null
        return String(value, Charsets.UTF_8)
    }    // ---------- EOCD / Signing Block 解析 ----------

    private data class Eocd(val pos: Int, val cdOffset: Int)

    private fun locateEocd(apk: ByteArray): Eocd {
        // 从末尾往前找 EOCD（允许 zip comment）
        var pos = apk.size - EOCD_SIG.size
        while (pos >= 0) {
            if (apk[pos] == EOCD_SIG[0] && apk[pos + 1] == EOCD_SIG[1] &&
                apk[pos + 2] == EOCD_SIG[2] && apk[pos + 3] == EOCD_SIG[3]
            ) {
                // 校验 comment 长度是否吻合
                val commentLen = (apk[pos + 20].toInt() and 0xFF) or ((apk[pos + 21].toInt() and 0xFF) shl 8)
                if (pos + 22 + commentLen == apk.size) {
                    val cdOffset = ByteBuffer.wrap(apk).order(ByteOrder.LITTLE_ENDIAN).getInt(pos + 16)
                    return Eocd(pos, cdOffset)
                }
            }
            pos--
        }
        throw ChannelException("未找到 EOCD，不是合法的 APK/ZIP")
    }

    /**
     * 定位 v2/v3 签名块（位于 Central Directory 之前）。
     * 结构：[size u64][pairs...][size u64][magic 16B]，size 含尾部 size 与 magic。
     */
    private fun findSigningBlock(apk: ByteArray, cdOffset: Int): ByteArray? {
        if (cdOffset < 24) return null
        val sizeFieldPos = cdOffset - 24
        val magicPos = cdOffset - 16
        if (!MAGIC.contentEquals(apk.copyOfRange(magicPos, magicPos + MAGIC.size))) return null
        // AOSP 标准：size 字段值 = block 总长 - 8（不含首 size 字段），块起点 = cdOffset - size - 8
        val blockSize = ByteBuffer.wrap(apk).order(ByteOrder.LITTLE_ENDIAN).getLong(sizeFieldPos)
        if (blockSize <= 0 || blockSize + 8 > cdOffset) return null
        val start = cdOffset - blockSize.toInt() - 8
        if (start < 0) return null
        // 校验开头 size 字段一致
        val headSize = ByteBuffer.wrap(apk).order(ByteOrder.LITTLE_ENDIAN).getLong(start)
        if (headSize != blockSize) return null
        return apk.copyOfRange(start, cdOffset)
    }

    /** 替换/插入指定 ID 的 pair，返回重建后的签名块 */
    private fun replacePair(block: ByteArray, targetId: Int, newValue: ByteArray): ByteArray {
        val bb = ByteBuffer.wrap(block).order(ByteOrder.LITTLE_ENDIAN)
        val pairsStart = 8
        val pairsEnd = block.size - 24 // 尾部 [size(8)][magic(16)]
        val out = ByteArrayOutputStream()
        var replaced = false
        var pos = pairsStart
        while (pos < pairsEnd) {
            val pairSize = bb.getLong(pos).toInt() // AOSP：size 不含自身 8 字节
            val pairTotal = pairSize + 8
            if (pairSize < 4 || pos + pairTotal > pairsEnd + 0) {
                throw ChannelException("签名块 pair 解析失败 @$pos")
            }
            val id = bb.getInt(pos + 8)
            if (id == targetId) {
                writePair(out, targetId, newValue)
                replaced = true
            } else {
                out.write(block, pos, pairTotal)
            }
            pos += pairTotal
        }
        if (!replaced) {
            writePair(out, targetId, newValue)
        }
        val payload = out.toByteArray()
        val totalSize = 8 + payload.size + 8 + MAGIC.size // 首 size + pairs + 尾 size + magic
        val sizeField = totalSize - 8 // AOSP 标准：size 字段不含首 size 字段自身
        val buf = ByteBuffer.allocate(totalSize).order(ByteOrder.LITTLE_ENDIAN)
        buf.putLong(sizeField.toLong())
        buf.put(payload)
        buf.putLong(sizeField.toLong())
        buf.put(MAGIC)
        return buf.array()
    }

    private fun buildNewBlock(id: Int, value: ByteArray): ByteArray {
        val pair = buildPair(id, value)
        val totalSize = 8 + pair.size + 8 + MAGIC.size
        val sizeField = totalSize - 8 // AOSP 标准：size 字段不含首 size 字段自身
        val buf = ByteBuffer.allocate(totalSize).order(ByteOrder.LITTLE_ENDIAN)
        buf.putLong(sizeField.toLong())
        buf.put(pair)
        buf.putLong(sizeField.toLong())
        buf.put(MAGIC)
        return buf.array()
    }

    /**
     * 单 pair（AOSP 格式，size 不含自身 8 字节）：
     * [size u64 = align4(4 + valueLen)][id u32][value][padding 到 4 字节对齐]
     */
    private fun buildPair(id: Int, value: ByteArray): ByteArray {
        val valueLen = align4(4 + value.size)
        val buf = ByteBuffer.allocate(8 + valueLen).order(ByteOrder.LITTLE_ENDIAN)
        buf.putLong(valueLen.toLong())
        buf.putInt(id)
        buf.put(value)
        return buf.array()
    }

    private fun writePair(out: ByteArrayOutputStream, id: Int, value: ByteArray) {
        out.write(buildPair(id, value))
    }

    /** 在签名块中查找指定 ID 的 pair value（无则 null；value 去除 4 字节对齐的尾部 \0 padding） */
    private fun findPair(block: ByteArray, targetId: Int): ByteArray? {
        val bb = ByteBuffer.wrap(block).order(ByteOrder.LITTLE_ENDIAN)
        val pairsEnd = block.size - 24
        var pos = 8
        while (pos < pairsEnd) {
            val pairSize = bb.getLong(pos).toInt() // AOSP：size 不含自身 8 字节
            val pairTotal = pairSize + 8
            if (pairSize < 4 || pos + pairTotal > pairsEnd) return null
            val id = bb.getInt(pos + 8)
            if (id == targetId) {
                val raw = block.copyOfRange(pos + 12, pos + pairTotal)
                var end = raw.size
                while (end > 0 && raw[end - 1] == 0.toByte()) end--
                return raw.copyOfRange(0, end)
            }
            pos += pairTotal
        }
        return null
    }

    private fun align4(v: Int): Int = (v + 3) and 3.inv()
}
