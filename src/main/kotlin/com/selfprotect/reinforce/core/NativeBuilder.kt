package com.selfprotect.reinforce.core

import java.io.File

/**
 * 壳 native 库构建器：用 NDK clang 交叉编译 libselfprotect.so（arm64-v8a + armeabi-v7a）。
 *
 * 流程：
 *  1. 探测 NDK（sdk/ndk 下取最高版本，或 ANDROID_NDK_HOME）
 *  2. 由 PayloadCrypto 同源密钥生成 key.h（SP_KEY_PART/SP_KEY_MASK，均为混淆字节，运行时 XOR 恢复）
 *  3. 释放 native 源码（resources/native 目录下的 .c 文件）并用 NDK clang 编译：
 *       clang -shared -fPIC -O2 -fvisibility=hidden -I<out> selfprotect.c aes.c sha256.c -llog
 *  4. 返回 Map<abi, so 文件>
 *
 * 产物按 ABI 注入加固 APK 的 lib/<abi>/libselfprotect.so。
 */
object NativeBuilder {

    class BuildException(msg: String) : RuntimeException(msg)

    private val NATIVE_SOURCES = listOf(
        "native/selfprotect.c",
        "native/aes.c",
        "native/sha256.c"
    )

    private val NATIVE_HEADERS = listOf(
        "native/aes.h",
        "native/sha256.h"
    )

    private data class Abi(
        val name: String,          // arm64-v8a
        val clangPrefix: String,   // aarch64-linux-android21
        val dir: String            // lib/arm64-v8a
    )

    private val ABIS = listOf(
        Abi("arm64-v8a", "aarch64-linux-android21", "lib/arm64-v8a"),
        Abi("armeabi-v7a", "armv7a-linux-androideabi21", "lib/armeabi-v7a")
    )

    fun detectNdk(sdkDir: File): File {
        val env = System.getenv("ANDROID_NDK_HOME")?.let(::File)?.takeIf { it.exists() }
        val sdkNdk = sdkDir.let { File(it, "ndk") }.takeIf { it.isDirectory }
        val ndk = env ?: sdkNdk
            ?: throw BuildException("未找到 NDK（sdk/ndk 或 ANDROID_NDK_HOME）")
        val candidates = if (ndk.name == "ndk" && ndk.listFiles() != null) {
            ndk.listFiles()!!.filter { it.isDirectory && it.name.firstOrNull()?.isDigit() == true }
        } else {
            listOf(ndk)
        }
        return candidates.maxByOrNull { it.name }
            ?: throw BuildException("NDK 目录为空：$ndk")
    }

    /** 释放 native 源码到 workDir 并生成 key.h，返回 (源码目录, key.h 文件) */
    private fun prepareSources(workDir: File): Pair<File, File> {
        val srcDir = File(workDir, "native-src").apply { mkdirs() }
        (NATIVE_SOURCES + NATIVE_HEADERS).forEach { resPath ->
            val target = File(srcDir, resPath.substringAfter("native/"))
            target.parentFile.mkdirs()
            val stream = NativeBuilder::class.java.classLoader.getResourceAsStream(resPath)
                ?: throw BuildException("插件资源缺失：$resPath")
            target.writeBytes(stream.readBytes())
        }
        // 生成 key.h：SP_KEY_PART / SP_KEY_MASK（与 PayloadCrypto 同源）
        val keyH = File(srcDir, "key.h")
        val sb = StringBuilder()
        sb.append("/* 自动生成：与 PayloadCrypto 密钥同源，请勿手改 */\n")
        sb.append("#ifndef SELFPROTECT_KEY_H\n#define SELFPROTECT_KEY_H\n")
        sb.append("static const unsigned char SP_KEY_PART[16] = {")
        sb.append(PayloadCrypto.KEY_PART.joinToString(",") { "0x%02X".format(it.toInt() and 0xFF) })
        sb.append("};\n")
        sb.append("static const unsigned char SP_KEY_MASK[16] = {")
        sb.append(PayloadCrypto.KEY_MASK.joinToString(",") { "0x%02X".format(it.toInt() and 0xFF) })
        sb.append("};\n")
        sb.append("#endif\n")
        keyH.writeText(sb.toString())
        return srcDir to keyH
    }

    /** 编译所有 ABI，返回 Map<abi, so 文件> */
    fun buildNative(sdkDir: File, workDir: File, log: (String) -> Unit = ::println): Map<String, File> {
        val ndk = detectNdk(sdkDir)
        log("      NDK: ${ndk.absolutePath}")
        val prebuilt = File(ndk, "toolchains/llvm/prebuilt")
        val host = prebuilt.listFiles()?.firstOrNull()?.takeIf { it.isDirectory }
            ?: throw BuildException("NDK 缺少 llvm/prebuilt 工具链：$prebuilt")
        val (srcDir, keyH) = prepareSources(workDir)
        val outRoot = File(workDir, "native-libs").apply { mkdirs() }
        val results = mutableMapOf<String, File>()

        for (abi in ABIS) {
            val clang = File(host, "bin/${abi.clangPrefix}-clang")
            if (!clang.exists()) {
                log("      跳过 ABI ${abi.name}（clang 不存在：$clang）")
                continue
            }
            val outSo = File(File(outRoot, abi.dir), "libselfprotect.so")
            outSo.parentFile.mkdirs()
            val cmd = listOf(
                clang.absolutePath,
                "-shared", "-fPIC", "-O2", "-fvisibility=hidden",
                "-DANDROID", "-ffunction-sections", "-fdata-sections",
                "-Wl,-s", // strip 符号表：避免函数名（如 check_frida_port）泄漏检测特征
                "-I", srcDir.absolutePath,
                "-o", outSo.absolutePath,
                File(srcDir, "selfprotect.c").absolutePath,
                File(srcDir, "aes.c").absolutePath,
                File(srcDir, "sha256.c").absolutePath,
                "-llog"
            )
            exec(cmd, "native 编译失败（${abi.name}）")
            results[abi.name] = outSo
            log("      ${abi.name}: ${outSo.absolutePath}（${outSo.length()}B）")
        }
        if (results.isEmpty()) throw BuildException("所有 ABI 编译失败")
        return results
    }

    private fun exec(cmd: List<String>, errorHint: String) {
        val pb = ProcessBuilder(cmd).redirectErrorStream(true)
        val proc = pb.start()
        val output = proc.inputStream.readBytes().toString(Charsets.UTF_8)
        val code = proc.waitFor()
        if (code != 0) {
            throw BuildException("$errorHint\n${cmd.joinToString(" ")}\n$output")
        }
    }
}
