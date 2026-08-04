package com.selfprotect.reinforce.core

import java.io.ByteArrayOutputStream
import java.io.File
import java.util.zip.CRC32
import java.util.zip.ZipEntry
import java.util.zip.ZipFile
import java.util.zip.ZipOutputStream

/**
 * APK 加固编排器（对应百度加固的打包侧流程）：
 *
 *   输入 APK ──┬─ 抽出全部 classes*.dex ──> zip ──> AES 加密 ──> assets/selfprotect/payload.dat
 *              ├─ 二进制改写 AndroidManifest.xml：application name -> 壳 StubApplication
 *              ├─ 原 Application 全限定名 ──> assets/selfprotect/config.txt
 *              ├─ 壳 DEX 写入包根 classes.dex（替换原入口 dex 位置）
 *              ├─ 剔除旧 v1 签名文件（META-INF 下的 .SF/.RSA/.DSA 与 MANIFEST.MF）
 *              └─ 其余条目（资源/图片/so/arsc）原样复制，保留 STORED/DEFLATED 方式
 *
 * 输出为未签名 APK，后续由 Signer 完成 zipalign + apksigner 重签。
 */
object ApkReinforcer {

    const val SHELL_APP_NAME = "com.selfprotect.StubApplication"
    const val PAYLOAD_PATH = "assets/selfprotect/payload.dat"
    const val CONFIG_PATH = "assets/selfprotect/config.txt"
    const val SIGNATURE_PATH = "assets/selfprotect/expected_sig.txt"
    const val PAYLOAD_HASH_PATH = "assets/selfprotect/payload_hash.txt"
    const val ASSETS_MAP_PATH = "assets/selfprotect/assets_map.txt"
    const val METHODS_PATH = "assets/selfprotect/methods.dat"
    const val ENC_ASSETS_PREFIX = "assets/enc/"

    /** 签名指纹掩码（与壳 StubApplication.SIG_MASK 同步；指纹 hex 转字节后逐字节异或） */
    private val SIG_MASK: ByteArray = byteArrayOf(
        0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x18.toByte(), 0x29.toByte(), 0x3A, 0x4B, 0x5C,
        0x6D, 0x7E, 0x8F.toByte(), 0x90.toByte(), 0xA1.toByte(), 0xB2.toByte(), 0xC3.toByte(), 0xD4.toByte(),
        0xE5.toByte(), 0xF6.toByte(), 0x07, 0x19.toByte(), 0x2A, 0x3B, 0x4C, 0x5D, 0x6E, 0x7F,
        0x88.toByte(), 0x99.toByte()
    )

    /** payload 哈希掩码（SHA-256 也是 32 字节，独立常量避免与指纹语义耦合） */
    private val PAYLOAD_MASK: ByteArray = byteArrayOf(
        0x5A, 0x6B, 0x7C, 0x1D, 0x2E, 0x3F, 0x40, 0x51.toByte(), 0x62, 0x73, (0x84).toByte(), 0x15,
        0x26, 0x37, 0x48, 0x59.toByte(), 0x6A, 0x7B, (0x8C).toByte(), 0x1E, 0x2F, 0x30, 0x41, 0x52.toByte(),
        0x63, 0x74, 0x05, 0x16, 0x27, 0x38, 0x49, 0x5B.toByte()
    )

    private val DEX_NAME_REGEX = Regex("^classes\\d*\\.dex$")

    /** classes.dex -> 0, classesN.dex -> N */
    private fun dexIndex(name: String): Int =
        name.removePrefix("classes").removeSuffix(".dex").let { if (it.isEmpty()) 0 else it.toIntOrNull() ?: Int.MAX_VALUE }

    class ReinforceException(msg: String) : RuntimeException(msg)

    /** 加固结果：原 Application 名 + 被抽取的方法数（0 = 未启用方法抽取） */
    data class ReinforceResult(val realAppName: String, val extractedMethodCount: Int)

    /**
     * @param inputApk  原始（已签名或未签名）APK
     * @param outputApk 输出未签名加固 APK
     * @param shellDex  壳 classes.dex 字节
     * @param expectedSignatureHex 输入 APK 签名证书 SHA-256（hex），写入壳内做防重打包校验；null 表示不预置
     * @param encryptedAssets 需要加密的 assets 路径规则（前缀/精确匹配），如 "private/"、"config.bin"；
     *                        为空表示不加密任何 assets
     * @param nativeLibs Map<abi, so 文件>（如 arm64-v8a -> libselfprotect.so），注入 APK 的 lib/<abi>/ 下
     * @param extractedMethods 关键方法抽取规则（如 "Lcom/foo/LicenseManager;"、"com.foo.pay.*"），
     *                         命中方法的 code_item 被抽空加密进 methods.dat，运行时壳内存回填
     */
    fun reinforce(
        inputApk: File,
        outputApk: File,
        shellDex: ByteArray,
        expectedSignatureHex: String? = null,
        encryptedAssets: List<String> = emptyList(),
        nativeLibs: Map<String, File> = emptyMap(),
        extractedMethods: List<String> = emptyList()
    ): ReinforceResult {
        require(inputApk.exists()) { "输入 APK 不存在：$inputApk" }

        ZipFile(inputApk).use { zip ->
            // 1. 收集原始 DEX（按数字序：classes.dex, classes2.dex, ..., classes10.dex，
            //    字符串排序会把 classes10.dex 排到 classes2.dex 前面，导致载荷内 dex 加载顺序错乱）
            val dexEntries = zip.entries().asSequence()
                .filter { DEX_NAME_REGEX.matches(it.name) && !it.isDirectory }
                .sortedWith(compareBy { dexIndex(it.name) })
                .toList()
            if (dexEntries.isEmpty()) throw ReinforceException("APK 中未找到 classes*.dex")

            // 1.5 需要加密的 assets（排除壳自身 selfprotect/ 目录）
            val assetsToEncrypt = zip.entries().asSequence()
                .filter { !it.isDirectory }
                .filter { it.name.startsWith("assets/") && !it.name.startsWith("assets/selfprotect/") }
                .filter { e -> encryptedAssets.any { rule -> e.name.removePrefix("assets/").startsWith(rule) } }
                .map { it.name }
                .toList()

            // 2. 改写 Manifest
            val manifestEntry = zip.getEntry("AndroidManifest.xml")
                ?: throw ReinforceException("APK 中未找到 AndroidManifest.xml")
            val rawManifest = zip.getInputStream(manifestEntry).readBytes()
            val (patchedManifest, realAppName) = AxmlEditor.replaceApplicationName(rawManifest, SHELL_APP_NAME)
            val appName = realAppName
                ?: throw ReinforceException("Manifest 未声明自定义 Application")

            // 3. 构建加密载荷：原始 dex 打包成 zip 后 AES 加密
            //    若配置了方法抽取规则：先抽空命中方法的 code_item（原字节单独加密进 methods.dat），
            //    载荷内 dex 只留桩，运行时壳内存回填（静态反编译看不到真实方法体）
            val extractedRecords = mutableListOf<DexMethodExtractor.ExtractedMethod>()
            val payloadZip = buildPayloadZip(zip, dexEntries.map { it.name }, extractedMethods, extractedRecords)
            val payloadEnc = PayloadCrypto.encrypt(payloadZip)
            // 自校验：确保壳运行时能解出来
            if (!PayloadCrypto.decrypt(payloadEnc).contentEquals(payloadZip)) {
                throw ReinforceException("载荷加解密自校验失败")
            }
            // 载荷完整性哈希（密文 SHA-256，掩码存储），壳侧解密前校验防篡改
            val payloadHashMasked = maskBytes(
                sha256(payloadEnc),
                PAYLOAD_MASK
            )

            // 4. 重建 APK
            outputApk.parentFile?.mkdirs()
            ZipOutputStream(outputApk.outputStream().buffered()).use { out ->
                // 4.1 壳 dex 放在最前面（约定：classes.dex 为首个 dex）
                writeEntry(out, "classes.dex", shellDex, ZipEntry.DEFLATED)

                // 4.2 复制其余条目（跳过原 dex、旧签名文件、将被替换的 Manifest、被加密的 assets）
                val skip = dexEntries.map { it.name }.toSet() +
                        assetsToEncrypt.toSet() +
                        setOf("AndroidManifest.xml", PAYLOAD_PATH, CONFIG_PATH, SIGNATURE_PATH, PAYLOAD_HASH_PATH, ASSETS_MAP_PATH, METHODS_PATH)
                zip.entries().asSequence().forEach { entry ->
                    val name = entry.name
                    if (entry.isDirectory || name in skip) return@forEach
                    if (name.startsWith("META-INF/") &&
                        (name.endsWith(".SF") || name.endsWith(".RSA") || name.endsWith(".DSA") ||
                                name.equals("META-INF/MANIFEST.MF", ignoreCase = true))
                    ) return@forEach
                    val bytes = zip.getInputStream(entry).readBytes()
                    writeEntry(out, name, bytes, entry.method, entry.time)
                }

                // 4.3 改写后的 Manifest
                writeEntry(out, "AndroidManifest.xml", patchedManifest, manifestEntry.method, manifestEntry.time)

                // 4.4 加密 assets（AES-CBC，与 payload 同算法；运行时 SecureAssets 透明解密）
                val assetsMapLines = mutableListOf<String>()
                assetsToEncrypt.sorted().forEach { name ->
                    val plain = zip.getInputStream(zip.getEntry(name)).readBytes()
                    val encName = ENC_ASSETS_PREFIX + name.removePrefix("assets/")
                    writeEntry(out, encName, PayloadCrypto.encrypt(plain), ZipEntry.DEFLATED)
                    assetsMapLines += "$encName|$name"
                }

                // 4.5 加密载荷、壳配置、防重打包指纹、assets 清单
                writeEntry(out, PAYLOAD_PATH, payloadEnc, ZipEntry.DEFLATED)
                writeEntry(out, CONFIG_PATH, appName.toByteArray(Charsets.UTF_8), ZipEntry.DEFLATED)
                if (expectedSignatureHex != null) {
                    writeEntry(out, SIGNATURE_PATH, maskSignature(expectedSignatureHex), ZipEntry.DEFLATED)
                }
                writeEntry(out, PAYLOAD_HASH_PATH, payloadHashMasked, ZipEntry.DEFLATED)
                if (assetsMapLines.isNotEmpty()) {
                    writeEntry(out, ASSETS_MAP_PATH, assetsMapLines.joinToString("\n").toByteArray(Charsets.UTF_8), ZipEntry.DEFLATED)
                }
                // 抽取的方法体（与 payload 同密钥 AES 加密；壳侧解密后按 codeOff 内存回填）
                if (extractedRecords.isNotEmpty()) {
                    val methodsEnc = PayloadCrypto.encrypt(DexMethodExtractor.serialize(extractedRecords))
                    if (!PayloadCrypto.decrypt(methodsEnc).contentEquals(DexMethodExtractor.serialize(extractedRecords))) {
                        throw ReinforceException("methods.dat 加解密自校验失败")
                    }
                    writeEntry(out, METHODS_PATH, methodsEnc, ZipEntry.DEFLATED)
                }

                // 4.6 注入壳 native 库 lib/<abi>/libselfprotect.so（STORE：so 需 16KB 页对齐，不压缩）
                nativeLibs.forEach { (abi, soFile) ->
                    writeEntry(out, "lib/$abi/libselfprotect.so", soFile.readBytes(), ZipEntry.STORED)
                }
            }
            return ReinforceResult(appName, extractedRecords.size)
        }
    }

    /** 指纹 hex 转字节后与掩码异或，避免以明文出现在 assets（配合壳侧 SIG_MASK 还原） */
    internal fun maskSignature(sha256Hex: String): ByteArray {
        val bytes = sha256Hex.lowercase().chunked(2).map { it.toInt(16).toByte() }.toByteArray()
        require(bytes.size == SIG_MASK.size) { "SHA-256 指纹长度不符: ${bytes.size}" }
        return ByteArray(bytes.size) { (bytes[it].toInt() xor SIG_MASK[it].toInt()).toByte() }
    }

    /** 原始字节与掩码异或 */
    private fun maskBytes(bytes: ByteArray, mask: ByteArray): ByteArray {
        require(bytes.size == mask.size) { "字节长度与掩码不符: ${bytes.size} != ${mask.size}" }
        return ByteArray(bytes.size) { (bytes[it].toInt() xor mask[it].toInt()).toByte() }
    }

    private fun sha256(data: ByteArray): ByteArray =
        java.security.MessageDigest.getInstance("SHA-256").digest(data)

    /**
     * 把原始 dex 按 classes.dex/classes2.dex... 顺序打入一个内存 zip。
     * extractRules 非空时，命中方法的 code_item 被抽空回填桩，原始字节收进 extractedOut。
     */
    private fun buildPayloadZip(
        zip: ZipFile,
        dexNames: List<String>,
        extractRules: List<String>,
        extractedOut: MutableList<DexMethodExtractor.ExtractedMethod>
    ): ByteArray {
        val bos = ByteArrayOutputStream()
        ZipOutputStream(bos).use { out ->
            dexNames.forEach { name ->
                val entry = zip.getEntry(name)
                var dexBytes = zip.getInputStream(entry).readBytes()
                if (extractRules.isNotEmpty()) {
                    val result = DexMethodExtractor.extract(dexBytes, dexIndex(name), extractRules)
                    dexBytes = result.dex
                    extractedOut += result.methods
                }
                val e = ZipEntry(name)
                e.method = ZipEntry.DEFLATED
                out.putNextEntry(e)
                out.write(dexBytes)
                out.closeEntry()
            }
        }
        return bos.toByteArray()
    }

    private fun writeEntry(
        out: ZipOutputStream,
        name: String,
        bytes: ByteArray,
        method: Int,
        time: Long = System.currentTimeMillis()
    ) {
        val e = ZipEntry(name)
        e.time = time
        if (method == ZipEntry.STORED) {
            // STORED 条目必须预先给出 size/crc（保留 arsc、so 等未压缩条目的存储方式）
            e.method = ZipEntry.STORED
            e.size = bytes.size.toLong()
            e.compressedSize = bytes.size.toLong()
            e.crc = CRC32().apply { update(bytes) }.value
        } else {
            e.method = ZipEntry.DEFLATED
        }
        out.putNextEntry(e)
        out.write(bytes)
        out.closeEntry()
    }
}
