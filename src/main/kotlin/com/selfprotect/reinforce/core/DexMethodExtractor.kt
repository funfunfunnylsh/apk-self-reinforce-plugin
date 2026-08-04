package com.selfprotect.reinforce.core

import java.security.MessageDigest
import java.util.zip.Adler32

/**
 * DEX 关键方法抽取器（"二代壳"轻量版：函数抽空 + 运行时内存回填）。
 *
 * 构建期：
 *  1. 解析 DEX（header → class_defs → class_data → code_item）
 *  2. 按规则匹配方法（支持整类 / 包前缀 / 精确方法 / 方法名前缀）
 *  3. 把命中方法的 code_item 原样抽出保存，原位回填最小合法桩
 *     （按返回类型生成 return-void / const+return / return-wide / return-object）
 *  4. 重算 DEX header 的 SHA-1 签名与 adler32 校验和
 *
 * 运行期（壳 StubApplication）：
 *  解密 methods.dat → 按 (dexIndex, codeOff) 把原始 code_item 回填进内存 dex → 再交给 ClassLoader。
 *  静态反编译只能看到桩，真实字节码只存在于内存。
 *
 * 不抽取的方法：
 *  - <init> / <clinit>（构造器必须调用父类构造，桩无法通过 ART 校验）
 *  - abstract / native（无 code_item）
 *  - code_item 比桩还小（如纯 return-void，没有保护价值）
 *
 * methods.dat 序列化格式（小端）：
 *  'S','P','M','E' | u32 version(=1) | u32 count
 *  每条记录：u16 dexIndex | u32 codeOff | u32 codeLen | code bytes
 */
object DexMethodExtractor {

    private const val MAGIC_SPME = 0x454d5053 // "SPME" little-endian
    private const val VERSION = 1

    /** 一条被抽取的方法记录 */
    data class ExtractedMethod(
        val dexIndex: Int,
        val codeOff: Int,
        val code: ByteArray,
        val display: String
    )

    data class ExtractResult(
        val dex: ByteArray,               // 抽空回填后的 dex（已重算签名/校验和）
        val methods: List<ExtractedMethod>,
        val skippedNoValue: Int           // code_item 太小而跳过（无保护价值）的数量
    )

    // ============================== 规则 ==============================

    private class Rule(raw: String) {
        val classPattern: String
        val classPrefix: Boolean
        val methodPattern: String?
        val methodPrefix: Boolean

        init {
            var r = raw.trim()
            // 兼容点号形式：com.foo.Bar / com.foo.Bar.method / com.foo.pay.*
            if (!r.startsWith("L")) {
                r = r.replace('.', '/')
                r = if (r.contains("->")) {
                    val idx = r.indexOf("->")
                    "L" + r.substring(0, idx) + ";" + r.substring(idx)
                } else if (r.endsWith("*")) {
                    // 包前缀：com.foo.pay.* -> Lcom/foo/pay/*（保留 '/' 边界，避免误匹配同前缀类）
                    "L" + r.trimEnd('*').trimEnd('/') + "/*"
                } else {
                    "L$r;"
                }
            }
            val arrow = r.indexOf("->")
            if (arrow >= 0) {
                classPattern = r.substring(0, arrow).removeSuffix("*")
                classPrefix = r.substring(0, arrow).endsWith("*")
                val m = r.substring(arrow + 2)
                methodPattern = m.removeSuffix("*").ifEmpty { null }
                methodPrefix = m.endsWith("*")
            } else {
                classPattern = r.removeSuffix("*")
                classPrefix = r.endsWith("*")
                methodPattern = null
                methodPrefix = false
            }
        }

        fun matchesClass(descriptor: String): Boolean =
            if (classPrefix) descriptor.startsWith(classPattern) else descriptor == classPattern

        fun matchesMethod(name: String): Boolean {
            val p = methodPattern ?: return true
            return if (methodPrefix) name.startsWith(p) else name == p
        }
    }

    // ============================== 小端读写 ==============================

    private class Reader(val buf: ByteArray) {
        fun u16(off: Int): Int =
            (buf[off].toInt() and 0xFF) or ((buf[off + 1].toInt() and 0xFF) shl 8)

        fun u32(off: Int): Long =
            (buf[off].toLong() and 0xFF) or
                    ((buf[off + 1].toLong() and 0xFF) shl 8) or
                    ((buf[off + 2].toLong() and 0xFF) shl 16) or
                    ((buf[off + 3].toLong() and 0xFF) shl 24)

        fun u32i(off: Int): Int = u32(off).toInt()

        /** 读 uleb128，返回 (值, 下一个偏移) */
        fun uleb(off: Int): Pair<Int, Int> {
            var result = 0
            var shift = 0
            var pos = off
            while (true) {
                val b = buf[pos].toInt() and 0xFF
                result = result or ((b and 0x7F) shl shift)
                pos++
                if (b and 0x80 == 0) break
                shift += 7
            }
            return result to pos
        }

        /** 读 sleb128 */
        fun sleb(off: Int): Pair<Int, Int> {
            var result = 0
            var shift = 0
            var pos = off
            var b: Int
            do {
                b = buf[pos].toInt() and 0xFF
                result = result or ((b and 0x7F) shl shift)
                shift += 7
                pos++
            } while (b and 0x80 != 0)
            if (shift < 32 && b and 0x40 != 0) {
                result = result or (-1 shl shift)
            }
            return result to pos
        }
    }

    private fun writeU16(buf: ByteArray, off: Int, v: Int) {
        buf[off] = (v and 0xFF).toByte()
        buf[off + 1] = ((v ushr 8) and 0xFF).toByte()
    }

    private fun writeU32(buf: ByteArray, off: Int, v: Long) {
        buf[off] = (v and 0xFF).toByte()
        buf[off + 1] = ((v ushr 8) and 0xFF).toByte()
        buf[off + 2] = ((v ushr 16) and 0xFF).toByte()
        buf[off + 3] = ((v ushr 24) and 0xFF).toByte()
    }

    /** 内部调试开关（诊断解析问题时用） */
    internal var debug = false

    // ============================== 主流程 ==============================

    /**
     * 对一个 dex 执行方法抽取。
     *
     * @param dex 原始 dex 字节（不会被修改，返回新数组）
     * @param dexIndex classes.dex=0, classes2.dex=2 ...
     * @param rules 抽取规则，如 "Lcom/foo/LicenseManager;"、"com.foo.pay.*"、"Lcom/foo/Bar;->check*"
     */
    fun extract(dex: ByteArray, dexIndex: Int, rules: List<String>): ExtractResult {
        val parsedRules = rules.map { Rule(it) }
        val r = Reader(dex)
        require(dex.size >= 0x70 && dex.copyOfRange(0, 4).contentEquals(byteArrayOf(0x64, 0x65, 0x78, 0x0A))) {
            "不是有效的 DEX 文件（magic 不匹配）"
        }

        val stringIdsSize = r.u32i(56)
        val stringIdsOff = r.u32i(60)
        val typeIdsOff = r.u32i(68)
        val protoIdsOff = r.u32i(76)
        val methodIdsOff = r.u32i(92)
        val classDefsSize = r.u32i(96)
        val classDefsOff = r.u32i(100)

        // string 读取（MUTF-8 与 UTF-8 在描述符/方法名场景等价）
        fun stringOf(strIdx: Int): String {
            if (strIdx < 0 || strIdx >= stringIdsSize) return ""
            val dataOff = r.u32i(stringIdsOff + strIdx * 4)
            var (utf16Len, pos) = r.uleb(dataOff)
            @Suppress("UNUSED_VARIABLE") val ignored = utf16Len
            val sb = StringBuilder()
            while (pos < dex.size && dex[pos].toInt() != 0) {
                sb.append(dex[pos].toInt().and(0xFF).toChar())
                pos++
            }
            return sb.toString()
        }

        fun typeDescriptor(typeIdx: Int): String =
            stringOf(r.u32i(typeIdsOff + typeIdx * 4))

        val out = dex.copyOf()
        val methods = mutableListOf<ExtractedMethod>()
        var skippedNoValue = 0

        for (ci in 0 until classDefsSize) {
            val defOff = classDefsOff + ci * 32
            val classIdx = r.u32i(defOff)
            val classDataOff = r.u32i(defOff + 24)
            if (classDataOff == 0) continue
            val classDesc = typeDescriptor(classIdx)
            if (parsedRules.none { it.matchesClass(classDesc) }) continue

            // class_data_item
            var pos = classDataOff
            val staticFieldsSize: Int
            val instanceFieldsSize: Int
            val directMethodsSize: Int
            val virtualMethodsSize: Int
            r.uleb(pos).also { staticFieldsSize = it.first; pos = it.second }
            r.uleb(pos).also { instanceFieldsSize = it.first; pos = it.second }
            r.uleb(pos).also { directMethodsSize = it.first; pos = it.second }
            r.uleb(pos).also { virtualMethodsSize = it.first; pos = it.second }

            // 跳过 fields
            repeat(staticFieldsSize + instanceFieldsSize) {
                r.uleb(pos).also { pos = it.second } // field_idx_diff
                r.uleb(pos).also { pos = it.second } // access_flags
            }

            // 遍历 direct + virtual methods
            // 注意：method_idx_diff 的累计在两个列表间是独立的（各自从 0 开始，DEX 规范）
            var methodIdx = 0
            repeat(directMethodsSize + virtualMethodsSize) { mi ->
                if (mi == directMethodsSize) methodIdx = 0 // virtual_methods 列表重新累计
                val idxDiff: Int
                val accessFlags: Int
                val codeOff: Int
                r.uleb(pos).also { idxDiff = it.first; pos = it.second }
                r.uleb(pos).also { accessFlags = it.first; pos = it.second }
                r.uleb(pos).also { codeOff = it.first; pos = it.second }
                methodIdx += idxDiff

                if (codeOff == 0) return@repeat // abstract/native

                // method_id: class_idx(u2), proto_idx(u2), name_idx(u4)
                val midOff = methodIdsOff + methodIdx * 8
                val protoIdx = r.u16(midOff + 2)
                val nameIdx = r.u32i(midOff + 4)
                val methodName = stringOf(nameIdx)
                if (debug) println("DBG visit $classDesc->$methodName idx=$methodIdx flags=0x${accessFlags.toString(16)} codeOff=$codeOff")

                if (methodName == "<init>" || methodName == "<clinit>") return@repeat
                if (parsedRules.none { it.matchesClass(classDesc) && it.matchesMethod(methodName) }) return@repeat

                // proto: shorty_idx(u4), return_type_idx(u4), parameters_off(u4)
                val protoOff = protoIdsOff + protoIdx * 12
                val returnTypeIdx = r.u32i(protoOff + 4)
                val paramsOff = r.u32i(protoOff + 8)
                val returnDesc = typeDescriptor(returnTypeIdx)

                // ins_size = this(非 static) + 参数槽（J/D 占 2）
                val isStatic = accessFlags and 0x0008 != 0
                var insSize = if (isStatic) 0 else 1
                if (paramsOff != 0) {
                    val paramCount = r.u32i(paramsOff)
                    for (pi in 0 until paramCount) {
                        val pType = typeDescriptor(r.u16(paramsOff + 4 + pi * 2))
                        insSize += if (pType == "J" || pType == "D") 2 else 1
                    }
                }

                val originalSize = codeItemSize(r, codeOff)
                val stub = buildStub(returnDesc, insSize)
                if (originalSize < stub.size) {
                    skippedNoValue++
                    return@repeat
                }

                // 保存原始 code_item，原位清零后写桩
                val original = dex.copyOfRange(codeOff, codeOff + originalSize)
                java.util.Arrays.fill(out, codeOff, codeOff + originalSize, 0.toByte())
                System.arraycopy(stub, 0, out, codeOff, stub.size)
                methods += ExtractedMethod(dexIndex, codeOff, original, "$classDesc->$methodName")
            }
        }

        if (methods.isNotEmpty()) {
            fixDexHeader(out)
        }
        return ExtractResult(out, methods, skippedNoValue)
    }

    /** 计算 code_item 完整大小（含 tries 与 catch handler 表） */
    private fun codeItemSize(r: Reader, off: Int): Int {
        val triesSize = r.u16(off + 6)
        val insnsSize = r.u32i(off + 12)
        var pos = off + 16 + insnsSize * 2
        if (triesSize > 0) {
            if (insnsSize % 2 != 0) pos += 2 // padding
            pos += triesSize * 8
            // encoded_catch_handler_list
            val listSize: Int
            r.uleb(pos).also { listSize = it.first; pos = it.second }
            repeat(listSize) {
                val count: Int
                r.sleb(pos).also { count = it.first; pos = it.second }
                repeat(kotlin.math.abs(count)) {
                    r.uleb(pos).also { pos = it.second } // type_idx
                    r.uleb(pos).also { pos = it.second } // addr
                }
                if (count <= 0) {
                    r.uleb(pos).also { pos = it.second } // catch_all_addr
                }
            }
        }
        return pos - off
    }

    /**
     * 生成最小合法桩 code_item（16 字节头 + insns）：
     *  - void  : return-void                                   (1 unit)
     *  - 数值  : const/4 v0, #0; return v0                     (2 units)
     *  - J/D   : const/4 v0, #0; return-wide v0                (2 units)
     *  - 引用  : const/4 v0, #0; return-object v0              (2 units)
     */
    private fun buildStub(returnDesc: String, insSize: Int): ByteArray {
        val insns: IntArray = when (returnDesc) {
            "V" -> intArrayOf(0x000E)                       // return-void
            "J", "D" -> intArrayOf(0x1200, 0x1000)          // const/4 v0,#0; return-wide v0
            else -> if (returnDesc.startsWith("L") || returnDesc.startsWith("[")) {
                intArrayOf(0x1200, 0x1100)                  // const/4 v0,#0; return-object v0
            } else {
                intArrayOf(0x1200, 0x0F00)                  // const/4 v0,#0; return v0
            }
        }
        val stub = ByteArray(16 + insns.size * 2)
        writeU16(stub, 0, maxOf(insSize, 1))  // registers_size
        writeU16(stub, 2, insSize)            // ins_size
        writeU16(stub, 4, 0)                  // outs_size
        writeU16(stub, 6, 0)                  // tries_size
        writeU32(stub, 8, 0)                  // debug_info_off
        writeU32(stub, 12, insns.size.toLong())
        insns.forEachIndexed { i, unit -> writeU16(stub, 16 + i * 2, unit) }
        return stub
    }

    /** 修改 dex 后重算 header 中的 SHA-1 signature 与 adler32 checksum */
    private fun fixDexHeader(dex: ByteArray) {
        val sha = MessageDigest.getInstance("SHA-1").digest(dex.copyOfRange(32, dex.size))
        System.arraycopy(sha, 0, dex, 12, 20)
        val adler = Adler32()
        adler.update(dex, 12, dex.size - 12)
        writeU32(dex, 8, adler.value)
    }

    // ============================== 序列化 ==============================

    /** 抽取记录 → methods.dat 明文字节（调用方负责加密） */
    fun serialize(methods: List<ExtractedMethod>): ByteArray {
        var total = 12
        methods.forEach { total += 10 + it.code.size }
        val out = ByteArray(total)
        writeU32(out, 0, MAGIC_SPME.toLong() and 0xFFFFFFFFL)
        writeU32(out, 4, VERSION.toLong())
        writeU32(out, 8, methods.size.toLong())
        var pos = 12
        methods.forEach { m ->
            writeU16(out, pos, m.dexIndex); pos += 2
            writeU32(out, pos, m.codeOff.toLong() and 0xFFFFFFFFL); pos += 4
            writeU32(out, pos, m.code.size.toLong()); pos += 4
            System.arraycopy(m.code, 0, out, pos, m.code.size); pos += m.code.size
        }
        return out
    }

    /** methods.dat 明文 → 抽取记录（测试/自校验用；壳侧 Java 有同格式解析） */
    fun parse(blob: ByteArray): List<ExtractedMethod> {
        val r = Reader(blob)
        require(r.u32(0) == (MAGIC_SPME.toLong() and 0xFFFFFFFFL)) { "methods.dat magic 不匹配" }
        require(r.u32i(4) == VERSION) { "methods.dat 版本不支持" }
        val count = r.u32i(8)
        var pos = 12
        val list = mutableListOf<ExtractedMethod>()
        repeat(count) {
            val dexIndex = r.u16(pos); pos += 2
            val codeOff = r.u32i(pos); pos += 4
            val len = r.u32i(pos); pos += 4
            val code = blob.copyOfRange(pos, pos + len); pos += len
            list += ExtractedMethod(dexIndex, codeOff, code, "")
        }
        return list
    }
}
