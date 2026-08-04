package com.selfprotect.reinforce

import com.selfprotect.reinforce.core.PgyerUploader
import com.selfprotect.reinforce.core.ReinforcePipeline
import com.selfprotect.reinforce.core.Signer
import org.gradle.api.DefaultTask
import org.gradle.api.tasks.Internal
import org.gradle.api.tasks.TaskAction
import java.io.File

/**
 * 加固任务。所有配置支持三种来源，优先级：命令行 -P 属性 > selfReinforce 扩展 > 默认值。
 *
 * 命令行示例（一条命令完成 打包+加固+重签+多渠道+蒲公英+钉钉）：
 * ./gradlew :app:selfReinforceApk \
 *   -PinputApk=app.apk -PoutputApk=out.apk \
 *   -Pks=ks.jks -PksPass=x -Palias=x -PkeyPass=x \
 *   -Pchannels=oppo,xiaomi -PchannelsFile=channels.txt \
 *   -PpgyerApiKey=xxx -PpgyerInstallPassword=123 \
 *   -PdingTalkWebhook=https://oapi.dingtalk.com/robot/send?access_token=xxx -PdingTalkSecret=SECxxx
 */
abstract class SelfReinforceTask : DefaultTask() {

    @get:Internal
    var selfExt: SelfReinforceExtension? = null

    @get:Internal
    var projDir: File? = null

    /** 读取命令行 -P 属性（空/空白视为未提供） */
    private fun prop(key: String): String? =
        (project.findProperty(key) as? String)?.takeIf { it.isNotBlank() }

    private fun propBool(key: String): Boolean? =
        prop(key)?.toBooleanStrictOrNull()

    @TaskAction
    fun run() {
        val ext = selfExt ?: throw IllegalStateException("selfReinforce 扩展未配置")

        // ===== 1. 输入 APK：-PinputApk > ext.inputApk > release 产物目录最新 APK =====
        val input = prop("inputApk")?.let(::File)
            ?: ext.inputApk.orNull?.asFile
            ?: run {
                val dir = File(project.buildDir, "outputs/apk/release")
                val apks = dir.listFiles { f -> f.isFile && f.name.endsWith(".apk") && !f.name.contains("selfprotect") }
                apks?.maxByOrNull { it.lastModified() }
                    ?: throw IllegalStateException(
                        "未找到 release APK（$dir）。\n" +
                        "提示：直接运行 ./gradlew :app:selfReinforceApk 会自动先执行 assembleRelease 再加固；\n" +
                        "或 -PinputApk=... 指定要加固的 APK。"
                    )
            }
        require(input.exists()) { "输入 APK 不存在：$input" }

        // ===== 2. 输出 APK：-PoutputApk > ext.outputApk > 输入同目录 app-selfprotect.apk =====
        val output = prop("outputApk")?.let(::File)
            ?: ext.outputApk.orNull?.asFile
            ?: File(input.parentFile, "app-selfprotect.apk")

        // ===== 3. SDK：-PsdkDir > ext.sdkDir > 自动探测 =====
        val sdk = prop("sdkDir")?.let(::File)
            ?: ext.sdkDir.orNull?.let(::File)
            ?: ReinforcePipeline.detectSdkDir(projDir)

        // ===== 4. 签名：-Pks > ext 显式 > android signingConfigs(release) > debug keystore =====
        val signing = resolveSigning(project, ext)

        // ===== 5. 多渠道/加密等配置合并（命令行 + 扩展）=====
        val cliChannels = prop("channels")?.split(",")?.map { it.trim() }?.filter { it.isNotEmpty() } ?: emptyList()
        val channels = (ext.channels + cliChannels).distinct()

        val cliEncAssets = prop("encryptedAssets")?.split(",")?.map { it.trim() }?.filter { it.isNotEmpty() } ?: emptyList()
        val encryptedAssets = (ext.encryptedAssets + cliEncAssets).distinct()

        val channelFile = prop("channelsFile")?.let(::File) ?: ext.channelFile.orNull?.asFile
        val channelOutputDir = prop("channelOutputDir")?.let(::File) ?: ext.channelOutputDir.orNull?.asFile

        // ===== 6. 蒲公英（可选）：-PpgyerApiKey > ext 配置 =====
        val pgyerKey = prop("pgyerApiKey") ?: ext.pgyerApiKey.orNull?.takeIf { it.isNotBlank() }
        val pgyerConfig = pgyerKey?.let {
            PgyerUploader.Config(
                apiKey = it,
                installType = prop("pgyerInstallType") ?: ext.pgyerInstallType.orNull?.takeIf(String::isNotBlank) ?: "2",
                installPassword = prop("pgyerInstallPassword") ?: ext.pgyerInstallPassword.orNull ?: "",
                updateDescription = prop("pgyerUpdateDescription") ?: ext.pgyerUpdateDescription.orNull ?: ""
            )
        }
        val pgyerUploadAll = propBool("pgyerUploadAllChannels") ?: ext.pgyerUploadAllChannels.getOrElse(false)

        // ===== 7. 钉钉（可选）：-PdingTalkWebhook > ext 配置 =====
        val dingTalkWebhook = prop("dingTalkWebhook") ?: ext.dingTalkWebhook.orNull?.takeIf { it.isNotBlank() }
        val dingTalkSecret = prop("dingTalkSecret") ?: ext.dingTalkSecret.orNull?.takeIf { it.isNotBlank() }
        val dingTalkKeyword = prop("dingTalkKeyword") ?: ext.dingTalkKeyword.orNull?.takeIf { it.isNotBlank() } ?: "Android"

        // ===== 8. 加固流水线 =====
        ReinforcePipeline.run(
            ReinforcePipeline.Config(
                inputApk = input,
                outputApk = output,
                sdkDir = sdk,
                signing = signing,
                encryptedAssets = encryptedAssets,
                channels = channels,
                channelFile = channelFile,
                channelOutputDir = channelOutputDir,
                pgyer = pgyerConfig,
                pgyerUploadAllChannels = pgyerUploadAll,
                dingTalkWebhook = dingTalkWebhook,
                dingTalkSecret = dingTalkSecret,
                dingTalkKeyword = dingTalkKeyword,
                workDir = File(project.buildDir, "self-reinforce")
            )
        ) { logger.lifecycle(it) }
    }

    /**
     * 签名解析，优先级：
     *  1. 命令行 -Pks（配套 -PksPass/-Palias/-PkeyPass）
     *  2. 扩展显式配置（storeFile 等 4 项）
     *  3. android extension 的 release signingConfig
     *  4. ~/.android/debug.keystore（androiddebugkey / android）
     */
    private fun resolveSigning(project: org.gradle.api.Project, ext: SelfReinforceExtension): Signer.SigningConfig? {
        // 1) 命令行 -Pks
        val cliKs = prop("ks")
        if (cliKs != null) {
            return Signer.SigningConfig(
                storeFile = File(cliKs),
                storePassword = prop("ksPass") ?: throw IllegalStateException("-Pks 时必须同时提供 -PksPass"),
                keyAlias = prop("alias") ?: throw IllegalStateException("-Pks 时必须同时提供 -Palias"),
                keyPassword = prop("keyPass") ?: throw IllegalStateException("-Pks 时必须同时提供 -PkeyPass")
            )
        }
        // 2) 扩展显式配置
        if (ext.storeFile.isPresent) {
            return Signer.SigningConfig(
                storeFile = ext.storeFile.get().asFile,
                storePassword = ext.storePassword.orNull ?: throw IllegalStateException("配置了 storeFile 时必须配置 storePassword"),
                keyAlias = ext.keyAlias.orNull ?: throw IllegalStateException("配置了 storeFile 时必须配置 keyAlias"),
                keyPassword = ext.keyPassword.orNull ?: throw IllegalStateException("配置了 storeFile 时必须配置 keyPassword")
            )
        }
        // 3) android signingConfigs(release)
        try {
            val androidExt = project.extensions.findByName("android")
            if (androidExt is com.android.build.api.dsl.ApplicationExtension) {
                val sc = androidExt.buildTypes.findByName("release")?.signingConfig
                val storeFile = sc?.storeFile
                if (storeFile != null) {
                    logger.lifecycle("[self-reinforce] 使用 android signingConfigs 的签名：${sc.name}")
                    return Signer.SigningConfig(
                        storeFile = storeFile,
                        storePassword = sc.storePassword ?: "",
                        keyAlias = sc.keyAlias ?: "",
                        keyPassword = sc.keyPassword ?: ""
                    )
                }
            }
        } catch (t: Throwable) {
            logger.warn("[self-reinforce] 读取 signingConfigs 失败：${t.message}")
        }
        // 4) debug keystore
        val debug = File(System.getProperty("user.home"), ".android/debug.keystore")
        if (debug.exists()) {
            logger.lifecycle("[self-reinforce] 使用默认 Android debug 签名：$debug")
            return Signer.SigningConfig(debug, "android", "androiddebugkey", "android")
        }
        logger.warn("[self-reinforce] 未找到任何签名配置，输出对齐后的未签名包")
        return null
    }
}
