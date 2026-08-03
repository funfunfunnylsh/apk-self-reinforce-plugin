package com.cdtec.selfreinforce.core

import java.nio.ByteBuffer
import java.nio.ByteOrder
import java.nio.charset.Charset

/**
 * 二进制 AndroidManifest.xml（AXML）编辑器。
 *
 * 只做一件事：把 <application android:name="真Application"> 的字符串值
 * 替换为壳 Application 的全限定名，并返回原值。
 *
 * 实现要点：
 *  - AXML 的属性值存的是字符串池索引，因此只需重建字符串池并替换对应下标的字符串，
 *    无需改动 XML body 中的任何字节；
 *  - 字符串池支持 UTF-8 / UTF-16LE 两种编码（依据 flags 的 UTF8_FLAG）；
 *  - 重建池后只需修正：池 chunk 的 size、文件头 size（后续 chunk 不含绝对偏移）。
 */
object AxmlEditor {

    private const val CHUNK_XML = 0x0003
    private const val CHUNK_STRING_POOL = 0x0001
    private const val CHUNK_START_TAG = 0x0102
    private const val UTF8_FLAG = 0x00000100
    private const val TYPE_STRING = 0x03
    private const val ANDROID_NS = "http://schemas.android.com/apk/res/android"

    /** 框架默认 AppComponentFactory，用于替换被抽走的 androidx CoreComponentFactory */
    private const val DEFAULT_COMPONENT_FACTORY = "android.app.AppComponentFactory"

    class AxmlException(msg: String) : RuntimeException(msg)

    private class StringPool(
        val chunkStart: Int,
        val chunkSize: Int,
        val utf8: Boolean,
        val styleCount: Int,
        val strings: MutableList<ByteArray>,   // 每条字符串的原始字节（按池编码）
        val stylesTail: ByteArray              // styles 区及其后 pool chunk 内的剩余字节（原样保留）
    )

    /**
     * @param axml      二进制 Manifest 内容
     * @param newAppName 壳 Application 全限定名
     * @return 原 application android:name（没有配置 name 时返回 null）
     */
    fun replaceApplicationName(axml: ByteArray, newAppName: String): Pair<ByteArray, String?> {
        val buf = ByteBuffer.wrap(axml).order(ByteOrder.LITTLE_ENDIAN)
        if (buf.shortAt(0).toInt() and 0xFFFF != CHUNK_XML) {
            throw AxmlException("不是合法的 AXML 文件")
        }
        val fileSize = buf.getInt(4)

        // 1. 定位并解析字符串池（第一个 chunk 必须是字符串池）
        var pool: StringPool? = null
        var appTag: AppTag? = null

        var off = buf.shortAt(2).toInt() and 0xFFFF // headerSize，通常 8
        while (off + 8 <= fileSize) {
            val type = buf.shortAt(off).toInt() and 0xFFFF
            val headerSize = buf.shortAt(off + 2).toInt() and 0xFFFF
            val size = buf.getInt(off + 4)
            when (type) {
                CHUNK_STRING_POOL -> pool = parseStringPool(buf, off, size)
                CHUNK_START_TAG -> {
                    if (pool != null && appTag == null) {
                        appTag = scanApplicationTag(buf, off, headerSize, pool)
                    }
                }
            }
            if (size <= 0) break
            off += size
        }
        if (pool == null) throw AxmlException("AXML 中未找到字符串池")
        val tag = appTag ?: throw AxmlException("AXML 中未找到 <application> 标签")

        // 2. 确定要替换/写入的属性值字符串下标
        var appNameValueIndex = tag.nameValueIndex
        var oldAppName = tag.oldName
        // 待插入的 android:name 属性（仅当标签原本没有 name 时非空）
        var insertNameAttr: IntArray? = null // [nsIdx, nameStrIdx, appNameIdx]

        if (appNameValueIndex < 0) {
            // <application> 无 android:name（默认 android.app.Application）：
            // 向字符串池追加 "name"/android 命名空间/壳类名，并准备一个待插入的 attribute
            val nameStrIdx = poolIndexOf(pool, "name") ?: poolAppend(pool, "name")
            val nsIdx = poolIndexOf(pool, ANDROID_NS) ?: poolAppend(pool, ANDROID_NS)
            val appNameIdx = poolAppend(pool, newAppName)
            appNameValueIndex = appNameIdx
            oldAppName = "android.app.Application"
            insertNameAttr = intArrayOf(nsIdx, nameStrIdx, appNameIdx)
        }

        // 3. 重建字符串池（替换目标下标 / 追加新字符串）
        pool.strings[appNameValueIndex] = encodeString(newAppName, pool.utf8)
        if (tag.nameRawValueIndex >= 0 && tag.nameRawValueIndex != appNameValueIndex) {
            // rawValue 与 typed value 指向不同字符串时，同步替换，避免 aapt/回显显示旧值
            pool.strings[tag.nameRawValueIndex] = encodeString(newAppName, pool.utf8)
        }
        if (tag.factoryValueIndex >= 0) {
            // appComponentFactory 指向的类（如 androidx CoreComponentFactory）已随原 dex 被抽走，
            // 框架创建 ClassLoader 时（早于 attachBaseContext）就要实例化它，必须换成框架自带实现
            pool.strings[tag.factoryValueIndex] = encodeString(DEFAULT_COMPONENT_FACTORY, pool.utf8)
        }
        val newPool = serializeStringPool(pool)

        // 4. 拼接新文件：文件头 + 新池 + 池之后的原始字节（必要时在 application 标签末尾插入 name 属性）
        val poolEnd = pool.chunkStart + pool.chunkSize
        val tail = axml.copyOfRange(poolEnd, fileSize)
        val newTail: ByteArray = if (insertNameAttr != null) {
            insertNameAttribute(tail, tag, poolEnd, insertNameAttr)
        } else {
            tail
        }
        val head = axml.copyOfRange(0, pool.chunkStart)
        val out = ByteBuffer.allocate(head.size + newPool.size + newTail.size).order(ByteOrder.LITTLE_ENDIAN)
        out.put(head)
        out.put(newPool)
        out.put(newTail)
        val result = out.array()
        // 修正文件总大小
        ByteBuffer.wrap(result).order(ByteOrder.LITTLE_ENDIAN).putInt(4, result.size)
        return result to oldAppName
    }

    private fun poolIndexOf(pool: StringPool, s: String): Int? {
        val charset = if (pool.utf8) Charsets.UTF_8 else Charset.forName("UTF-16LE")
        for (i in pool.strings.indices) {
            if (String(pool.strings[i], charset) == s) return i
        }
        return null
    }

    private fun poolAppend(pool: StringPool, s: String): Int {
        pool.strings.add(encodeString(s, pool.utf8))
        return pool.strings.size - 1
    }

    /**
     * 在 <application> start-tag chunk 末尾追加一个 android:name 属性（20 字节）。
     * tail 为字符串池之后的原始字节；返回插入后的新 tail。
     */
    private fun insertNameAttribute(
        tail: ByteArray,
        tag: AppTag,
        poolEnd: Int,
        attrRefs: IntArray
    ): ByteArray {
        val nsIdx = attrRefs[0]
        val nameStrIdx = attrRefs[1]
        val appNameIdx = attrRefs[2]

        // attribute: ResXMLTree_attribute { ns u32, name u32, rawValue u32, Res_value(8B) }
        val attr = ByteBuffer.allocate(20).order(ByteOrder.LITTLE_ENDIAN)
            .putInt(nsIdx)
            .putInt(nameStrIdx)
            .putInt(appNameIdx)
            .putShort(8)          // Res_value.size
            .put(0)               // Res_value.res0
            .put(TYPE_STRING.toByte())
            .putInt(appNameIdx)   // Res_value.data = 字符串池下标
            .array()

        // start-tag chunk 在 tail 内的相对位置
        val chunkRel = tag.chunkStart - poolEnd
        // 属性区结尾（相对 tail）：chunk 内 attrOff 相对 chunkStart，即 chunkRel + attrStart + headerSize
        val insertRel = chunkRel + tag.headerSize + tag.attrStart + tag.attrCount * tag.attrSize

        val out = ByteBuffer.allocate(tail.size + 20).order(ByteOrder.LITTLE_ENDIAN)
        out.put(tail, 0, insertRel)
        out.put(attr)
        out.put(tail, insertRel, tail.size - insertRel)
        val newTail = out.array()

        // 更新 start-tag chunk：attributeCount(+1) 与 chunk size(+20)
        val bb = ByteBuffer.wrap(newTail).order(ByteOrder.LITTLE_ENDIAN)
        val attrCountOffset = chunkRel + tag.headerSize + 12 // attrCount 位于 body+12
        bb.putShort(attrCountOffset, (tag.attrCount + 1).toShort())
        bb.putInt(chunkRel + 4, bb.getInt(chunkRel + 4) + 20)
        return newTail
    }

    // ---------- 解析 ----------

    private fun parseStringPool(buf: ByteBuffer, chunkStart: Int, chunkSize: Int): StringPool {
        val stringCount = buf.getInt(chunkStart + 8)
        val styleCount = buf.getInt(chunkStart + 12)
        val flags = buf.getInt(chunkStart + 16)
        val stringsStart = buf.getInt(chunkStart + 20)
        val stylesStart = buf.getInt(chunkStart + 24)
        val utf8 = (flags and UTF8_FLAG) != 0

        val offsetsBase = chunkStart + 28
        val dataBase = chunkStart + stringsStart
        val strings = ArrayList<ByteArray>(stringCount)
        for (i in 0 until stringCount) {
            val rel = buf.getInt(offsetsBase + i * 4)
            val p = dataBase + rel
            val bytes = if (utf8) readUtf8(buf, p) else readUtf16(buf, p)
            strings.add(bytes)
        }
        // styles 区（一般 styleCount=0）到 pool chunk 末尾原样保留
        val tailStart = if (styleCount > 0) chunkStart + stylesStart else chunkStart + chunkSize
        val stylesTail = if (styleCount > 0 && tailStart < chunkStart + chunkSize) {
            ByteArray(chunkStart + chunkSize - tailStart) { buf.get(tailStart + it) }
        } else ByteArray(0)
        return StringPool(chunkStart, chunkSize, utf8, styleCount, strings, stylesTail)
    }

    /** 读取 UTF-8 字符串原始字节（去掉长度前缀与结尾 NUL） */
    private fun readUtf8(buf: ByteBuffer, p: Int): ByteArray {
        var pos = p
        var charLen = buf.get(pos).toInt() and 0xFF
        pos++
        if (charLen and 0x80 != 0) {
            charLen = ((charLen and 0x7F) shl 8) or (buf.get(pos).toInt() and 0xFF)
            pos++
        }
        var byteLen = buf.get(pos).toInt() and 0xFF
        pos++
        if (byteLen and 0x80 != 0) {
            byteLen = ((byteLen and 0x7F) shl 8) or (buf.get(pos).toInt() and 0xFF)
            pos++
        }
        return ByteArray(byteLen) { buf.get(pos + it) }
    }

    /** 读取 UTF-16LE 字符串原始字节（去掉长度前缀与结尾 0x0000） */
    private fun readUtf16(buf: ByteBuffer, p: Int): ByteArray {
        var pos = p
        var len = buf.shortAt(pos).toInt() and 0xFFFF
        pos += 2
        if (len and 0x8000 != 0) {
            len = ((len and 0x7FFF) shl 16) or (buf.shortAt(pos).toInt() and 0xFFFF)
            pos += 2
        }
        return ByteArray(len * 2) { buf.get(pos + it) }
    }

    /**
     * 扫描 start-tag chunk：若是 <application> 标签则返回其完整布局信息。
     * nameValueIndex 为 -1 表示标签没有 android:name（默认 android.app.Application）。
     */
    private fun scanApplicationTag(
        buf: ByteBuffer,
        chunkStart: Int,
        headerSize: Int,
        pool: StringPool
    ): AppTag? {
        // start-tag: header(type,headerSize,size) lineNumber comment ns name attrStart attrSize attrCount idIndex classIndex styleIndex
        val tagNameIdx = buf.getInt(chunkStart + 20)
        if (poolString(pool, tagNameIdx) != "application") return null
        val attrCount = buf.shortAt(chunkStart + 28).toInt() and 0xFFFF
        // attrStart 是相对 tag body（ns 字段）起始的偏移
        val attrStart = buf.shortAt(chunkStart + 24).toInt() and 0xFFFF
        val attrSize = buf.shortAt(chunkStart + 26).toInt() and 0xFFFF
        val attrOff = chunkStart + headerSize + attrStart
        var nameIndex = -1
        var nameRawValueIndex = -1
        var oldName: String? = null
        var factoryIndex = -1
        for (i in 0 until attrCount) {
            val a = attrOff + i * attrSize
            val nsIdx = buf.getInt(a)
            val aNameIdx = buf.getInt(a + 4)
            val rawValueIdx = buf.getInt(a + 8)
            val dataType = buf.get(a + 15).toInt() and 0xFF
            val data = buf.getInt(a + 16)
            if (dataType != TYPE_STRING || data < 0) continue
            val ns = if (nsIdx >= 0) poolString(pool, nsIdx) else null
            if (ns != null && ns != ANDROID_NS) continue
            val attrName = poolString(pool, aNameIdx) ?: continue
            when (attrName) {
                "name" -> {
                    val value = poolString(pool, data) ?: continue
                    nameIndex = data
                    nameRawValueIndex = if (rawValueIdx >= 0) rawValueIdx else -1
                    oldName = value
                }
                "appComponentFactory" -> factoryIndex = data
            }
        }
        return AppTag(
            chunkStart = chunkStart,
            headerSize = headerSize,
            attrStart = attrStart,
            attrSize = attrSize,
            attrCount = attrCount,
            nameValueIndex = nameIndex,
            oldName = oldName,
            nameRawValueIndex = nameRawValueIndex,
            factoryValueIndex = factoryIndex
        )
    }

    private data class AppTag(
        val chunkStart: Int,       // start-tag chunk 起始（含 chunk header）
        val headerSize: Int,
        val attrStart: Int,        // 第一个 attribute 相对 body 起始的偏移
        val attrSize: Int,
        val attrCount: Int,
        val nameValueIndex: Int,   // -1 = 无 android:name
        val oldName: String?,
        val nameRawValueIndex: Int,
        val factoryValueIndex: Int
    )

    // ---------- 序列化 ----------

    private fun poolString(pool: StringPool, idx: Int): String? {
        if (idx < 0 || idx >= pool.strings.size) return null
        val charset: Charset = if (pool.utf8) Charsets.UTF_8 else Charset.forName("UTF-16LE")
        return String(pool.strings[idx], charset)
    }

    private fun encodeString(s: String, utf8: Boolean): ByteArray =
        s.toByteArray(if (utf8) Charsets.UTF_8 else Charset.forName("UTF-16LE"))

    /** 重新序列化字符串池 chunk（保持原编码），返回完整的 pool chunk 字节 */
    private fun serializeStringPool(pool: StringPool): ByteArray {
        val stringCount = pool.strings.size
        val headerSize = 28
        val offsetsSize = stringCount * 4
        val stringsStart = headerSize + offsetsSize

        // 先编码所有字符串数据，得到总长度
        val encoded = pool.strings.map { encodeEntry(it, pool.utf8) }
        val dataLen = encoded.sumOf { it.size }
        val stylesOffset = stringsStart + dataLen
        val chunkSize = align4(stylesOffset + pool.stylesTail.size)

        val out = ByteBuffer.allocate(chunkSize).order(ByteOrder.LITTLE_ENDIAN)
        out.putShort(CHUNK_STRING_POOL.toShort())
        out.putShort(headerSize.toShort())
        out.putInt(chunkSize)
        out.putInt(stringCount)
        out.putInt(pool.styleCount)
        out.putInt(if (pool.utf8) UTF8_FLAG else 0)
        out.putInt(stringsStart)
        out.putInt(if (pool.stylesTail.isEmpty()) 0 else stylesOffset)
        var rel = 0
        for (e in encoded) {
            out.putInt(rel)
            rel += e.size
        }
        for (e in encoded) out.put(e)
        out.put(pool.stylesTail)
        while (out.position() < chunkSize) out.put(0)
        return out.array()
    }

    /** 编码单条字符串（含长度前缀与结尾 NUL） */
    private fun encodeEntry(raw: ByteArray, utf8: Boolean): ByteArray {
        val charLen = if (utf8) {
            // UTF-8：前缀为字符数，统计逻辑字符数
            String(raw, Charsets.UTF_8).length
        } else {
            raw.size / 2
        }
        val byteLen = raw.size
        return if (utf8) {
            val header = if (charLen > 0x7F || byteLen > 0x7F) 4 else 2
            val b = ByteBuffer.allocate(header + byteLen + 1).order(ByteOrder.LITTLE_ENDIAN)
            putLen8(b, charLen)
            putLen8(b, byteLen)
            b.put(raw)
            b.put(0)
            b.array()
        } else {
            val header = if (charLen > 0x7FFF) 4 else 2
            val b = ByteBuffer.allocate(header + byteLen + 2).order(ByteOrder.LITTLE_ENDIAN)
            putLen16(b, charLen)
            b.put(raw)
            b.putShort(0)
            b.array()
        }
    }

    private fun putLen8(b: ByteBuffer, len: Int) {
        if (len > 0x7F) {
            b.put(((len shr 8) or 0x80).toByte())
            b.put((len and 0xFF).toByte())
        } else {
            b.put(len.toByte())
        }
    }

    private fun putLen16(b: ByteBuffer, len: Int) {
        if (len > 0x7FFF) {
            b.putShort(((len shr 16) or 0x8000).toShort())
            b.putShort((len and 0xFFFF).toShort())
        } else {
            b.putShort(len.toShort())
        }
    }

    private fun align4(v: Int): Int = (v + 3) and 3.inv()

    private fun ByteBuffer.shortAt(pos: Int): Short = this.getShort(pos)
}
