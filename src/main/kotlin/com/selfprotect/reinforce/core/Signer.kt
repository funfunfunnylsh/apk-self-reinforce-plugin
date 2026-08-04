package com.selfprotect.reinforce.core

import java.io.File

/**
 * 对齐与重签名：zipalign（保持 .so 页对齐）+ apksigner（v1+v2）。
 * 签名参数风格与现有 apk-reinforce-sign-plugin 保持一致。
 */
object Signer {

    class SignException(msg: String) : RuntimeException(msg)

    data class SigningConfig(
        val storeFile: File,
        val storePassword: String,
        val keyAlias: String,
        val keyPassword: String
    )

    /**
     * @param inputApk  加固后的未签名 APK
     * @param outputApk 最终输出 APK（对齐 + 签名）
     * @param sdkDir    Android SDK 目录
     * @param config    为 null 时只做对齐，不签名（便于离线验证结构）
     */
    fun alignAndSign(inputApk: File, outputApk: File, sdkDir: File, config: SigningConfig?) {
        val aligned = if (config != null) {
            File(outputApk.parentFile, outputApk.nameWithoutExtension + "-aligned.apk")
        } else outputApk

        // 1. zipalign：align=4 字节对齐；-P 16 保证 arm64 .so 16KB 页对齐（与 -p 互斥，二选一）
        val zipalign = try {
            ShellDexBuilder.findBuildTool(sdkDir, "zipalign")
        } catch (e: Exception) {
            null
        }
        if (zipalign != null) {
            exec(
                listOf(zipalign.absolutePath, "-f", "-P", "16", "4",
                    inputApk.absolutePath, aligned.absolutePath),
                "zipalign 失败"
            )
        } else {
            System.err.println("[self-reinforce] 警告：未找到 zipalign，跳过分页对齐（可能影响 extractNativeLibs=false 的 so 加载）")
            inputApk.copyTo(aligned, overwrite = true)
        }

        // 2. apksigner 重签
        if (config != null) {
            val apksigner = ShellDexBuilder.findBuildToolLib(sdkDir, "apksigner.jar")
            exec(
                listOf(
                    "java", "-jar", apksigner.absolutePath, "sign",
                    "--v1-signing-enabled", "true",
                    "--v2-signing-enabled", "true",
                    "--v3-signing-enabled", "false",
                    "--ks", config.storeFile.absolutePath,
                    "--ks-pass", "pass:${config.storePassword}",
                    "--ks-key-alias", config.keyAlias,
                    "--key-pass", "pass:${config.keyPassword}",
                    "--out", outputApk.absolutePath,
                    aligned.absolutePath
                ),
                "apksigner 签名失败"
            )
            // 3. 校验
            exec(listOf("java", "-jar", apksigner.absolutePath, "verify", "--print-certs", outputApk.absolutePath),
                "签名校验失败")
            aligned.delete()
        }
    }

    private fun exec(cmd: List<String>, errorHint: String) {
        val process = ProcessBuilder(cmd).redirectErrorStream(true).start()
        val output = process.inputStream.bufferedReader().readText()
        val code = process.waitFor()
        if (code != 0) {
            throw SignException("$errorHint (exit=$code)\n输出：$output")
        }
    }
}
