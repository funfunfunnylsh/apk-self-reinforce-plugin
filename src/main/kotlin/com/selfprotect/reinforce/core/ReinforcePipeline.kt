package com.selfprotect.reinforce.core

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
        val channelFile: File? = null,
        val channelOutputDir: File? = null,
        val pgyer: PgyerUploader.Config? = null,
        val pgyerUploadAllChannels: Boolean = false,
        val dingTalkWebhook: String? = null,
        val dingTalkSecret: String? = null,
        val dingTalkKeyword: String = "Android",
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

        // 多渠道（可选）：配置渠道 + 渠道文件合并去重，写入 Signing Block 无需重签名
        val allChannels = ChannelLoader.merge(config.channels, config.channelFile)
        val channelApks = if (allChannels.isNotEmpty()) {
            writeChannels(config, allChannels, log)
        } else {
            emptyMap()
        }

        // 蒲公英上传（可选）
        val pgyerResults = if (config.pgyer != null) {
            uploadToPgyer(config, channelApks, log)
        } else {
            emptyList()
        }

        // 钉钉通知（可选）
        if (!config.dingTalkWebhook.isNullOrBlank()) {
            sendDingTalk(config, channelApks, pgyerResults, log)
        }
    }

    /** 为每个渠道复制加固包并写入渠道信息（walle 方案，保留原签名），返回 渠道名 -> 渠道包 */
    private fun writeChannels(config: Config, channels: List<String>, log: (String) -> Unit): Map<String, File> {
        val outDir = config.channelOutputDir ?: File(config.outputApk.parentFile, "channels")
        outDir.mkdirs()
        val baseBytes = config.outputApk.readBytes()
        val baseName = config.outputApk.name.removeSuffix(".apk")
        val result = LinkedHashMap<String, File>()
        channels.forEach { channel ->
            val channelApk = File(outDir, "${baseName}_${channel}.apk")
            channelApk.writeBytes(ChannelWriter.writeChannel(baseBytes, channel))
            val verify = ChannelWriter.readChannel(channelApk.readBytes())
            if (verify != channel) {
                throw IllegalStateException("渠道 $channel 写入校验失败：读到 $verify")
            }
            log("      渠道包：${channelApk.name}（channel=$channel）")
            result[channel] = channelApk
        }
        return result
    }

    /** 蒲公英上传：默认主包；pgyerUploadAllChannels=true 时同时上传全部渠道包 */
    private fun uploadToPgyer(
        config: Config,
        channelApks: Map<String, File>,
        log: (String) -> Unit
    ): List<Pair<String, PgyerUploader.Result>> {
        val pgyer = config.pgyer!!
        val results = mutableListOf<Pair<String, PgyerUploader.Result>>()
        val targets = mutableListOf<Pair<String, File>>("主包" to config.outputApk)
        if (config.pgyerUploadAllChannels) {
            channelApks.forEach { (ch, f) -> targets += "渠道-$ch" to f }
        }
        targets.forEach { (label, file) ->
            val r = PgyerUploader.uploadAndWait(file, pgyer) { log("      [蒲公英] $it") }
            log("      [蒲公英] $label 上传完成：${r.buildShortcutUrl}")
            results += label to r
        }
        return results
    }

    /** 钉钉 markdown 通知（标题/分支/版本/蒲公英下载与二维码/包体/变更） */
    private fun sendDingTalk(
        config: Config,
        channelApks: Map<String, File>,
        pgyerResults: List<Pair<String, PgyerUploader.Result>>,
        log: (String) -> Unit
    ) {
        val keyword = config.dingTalkKeyword
        val title = "$keyword Android 包更新"
        val sb = StringBuilder()
        sb.append("### ").append(title).append("\n\n")
        sb.append("包名: ").append(config.inputApk.name.removeSuffix(".apk")).append("\n\n")
        sb.append("加固包: ").append(config.outputApk.name).append("\n\n")
        sb.append("包体: ").append(config.outputApk.length() / 1024 / 1024).append(" MB\n\n")
        sb.append("构建时间: ").append(java.text.SimpleDateFormat("yyyy-MM-dd HH:mm:ss").format(java.util.Date())).append("\n\n")
        if (channelApks.isNotEmpty()) {
            sb.append("**渠道包**\n\n").append(channelApks.keys.joinToString(" / ")).append("\n\n")
        }
        if (pgyerResults.isNotEmpty()) {
            sb.append("**蒲公英**\n\n")
            pgyerResults.forEach { (label, r) ->
                sb.append("- ").append(label).append("\n")
                if (r.buildShortcutUrl.isNotBlank()) sb.append("  下载: ").append(r.buildShortcutUrl).append("\n")
                if (r.buildQRCodeURL.isNotBlank()) sb.append("  ![二维码](").append(r.buildQRCodeURL).append(")\n")
                if (r.buildVersion.isNotBlank()) sb.append("  版本: ").append(r.buildVersion).append("\n")
            }
            config.pgyer?.installPassword?.takeIf { it.isNotBlank() }?.let {
                sb.append("\n安装密码: ").append(it).append("\n")
            }
        }
        val resp = DingTalkNotifier.sendMarkdown(
            config.dingTalkWebhook!!, config.dingTalkSecret, "### $title", sb.toString()
        )
        log("      [钉钉] 通知发送成功（errcode=0）")
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
