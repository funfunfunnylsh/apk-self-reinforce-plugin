package com.cdtec.selfreinforce.core

import java.io.File

/**
 * 加固流水线总入口：壳编译 → APK 加固 → 对齐 → 重签。
 * Gradle Task 与命令行 CLI 共用。
 */
object ReinforcePipeline {

    data class Config(
        val inputApk: File,
        val outputApk: File,
        val sdkDir: File,
        val signing: Signer.SigningConfig? = null,
        val encryptedAssets: List<String> = emptyList(),
        val channels: List<String> = emptyList(),
        val channelOutputDir: File? = null,
        val workDir: File = File(outputApk.parentFile ?: File("."), "self-reinforce-work")
    )

    fun run(config: Config, log: (String) -> Unit = ::println) {
        config.workDir.mkdirs()

        log("[1/4] 编译壳 DEX（javac + d8）...")
        val shellDex = ShellDexBuilder.buildShellDex(config.sdkDir, config.workDir)
        log("      壳 classes.dex：${shellDex.size} 字节")

        // 防重打包：提取输入 APK 签名证书 SHA-256（重签用同一 keystore，指纹一致；未配置签名则不预置）
        val expectedSignature = if (config.signing != null) {
            val sig = extractSignatureSha256(config.inputApk, config.sdkDir)
            log("      签名指纹：$sig")
            sig
        } else {
            log("      未配置签名，跳过防重打包指纹预置")
            null
        }

        log("[2/4] 加固 APK（DEX 抽取加密 + Manifest 改写 + 注入壳${if (config.encryptedAssets.isNotEmpty()) " + assets 加密" else ""}）...")
        val unsigned = File(config.workDir, "unsigned-reinforced.apk")
        val realApp = ApkReinforcer.reinforce(
            config.inputApk, unsigned, shellDex,
            expectedSignatureHex = expectedSignature,
            encryptedAssets = config.encryptedAssets
        )
        log("      原 Application：$realApp（已写入 ${ApkReinforcer.CONFIG_PATH}）")
        if (config.encryptedAssets.isNotEmpty()) {
            log("      assets 加密规则：${config.encryptedAssets}")
        }
        log("      未签名包：${unsigned.absolutePath}（${unsigned.length() / 1024 / 1024} MB）")

        log("[3/4] zipalign 对齐...")
        log("[4/4] apksigner 重签${if (config.signing == null) "（未配置签名，仅对齐输出）" else ""}...")
        Signer.alignAndSign(unsigned, config.outputApk, config.sdkDir, config.signing)
        log("完成：${config.outputApk.absolutePath}")

        // 多渠道（可选）：写入 Signing Block，无需重签名
        if (config.channels.isNotEmpty()) {
            writeChannels(config, log)
        }
    }

    /** 为每个渠道复制加固包并写入渠道信息（walle 方案，保留原签名） */
    private fun writeChannels(config: Config, log: (String) -> Unit) {
        val outDir = config.channelOutputDir ?: File(config.outputApk.parentFile, "channels")
        outDir.mkdirs()
        val baseBytes = config.outputApk.readBytes()
        val baseName = config.outputApk.name.removeSuffix(".apk")
        config.channels.forEach { channel ->
            val channelApk = File(outDir, "${baseName}_${channel}.apk")
            channelApk.writeBytes(ChannelWriter.writeChannel(baseBytes, channel))
            val verify = ChannelWriter.readChannel(channelApk.readBytes())
            if (verify != channel) {
                throw IllegalStateException("渠道 $channel 写入校验失败：读到 $verify")
            }
            log("      渠道包：${channelApk.name}（channel=$channel）")
        }
    }

    /** 用 apksigner 提取 APK 签名证书 SHA-256（hex 小写） */
    fun extractSignatureSha256(inputApk: File, sdkDir: File): String {
        val apksigner = ShellDexBuilder.findBuildToolLib(sdkDir, "apksigner.jar")
        val output = execCapture(listOf("java", "-jar", apksigner.absolutePath, "verify", "--print-certs", inputApk.absolutePath))
        val match = Regex("SHA-256\\s+digest:\\s*([0-9a-fA-F]{64})").find(output)
            ?: throw IllegalStateException("无法从 apksigner 输出解析签名指纹")
        return match.groupValues[1].lowercase()
    }

    private fun execCapture(cmd: List<String>): String {
        val process = ProcessBuilder(cmd).redirectErrorStream(true).start()
        val output = process.inputStream.bufferedReader().readText()
        if (process.waitFor() != 0) {
            throw IllegalStateException("命令执行失败：${cmd.joinToString(" ")}\n$output")
        }
        return output
    }

    /** 按常见优先级探测本机 SDK 目录 */
    fun detectSdkDir(projectDir: File? = null): File {
        System.getenv("ANDROID_HOME")?.takeIf { it.isNotBlank() }?.let { return File(it) }
        System.getenv("ANDROID_SDK_ROOT")?.takeIf { it.isNotBlank() }?.let { return File(it) }
        if (projectDir != null) {
            val localProps = File(projectDir, "local.properties")
            if (localProps.exists()) {
                localProps.readLines().firstOrNull { it.startsWith("sdk.dir") }
                    ?.substringAfter("=")?.trim()?.let { return File(it) }
            }
        }
        val macDefault = File(System.getProperty("user.home"), "Library/Android/sdk")
        if (macDefault.exists()) return macDefault
        throw IllegalStateException("无法探测 Android SDK 目录，请显式配置 sdkDir")
    }
}
