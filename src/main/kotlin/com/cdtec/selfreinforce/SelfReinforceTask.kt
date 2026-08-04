package com.cdtec.selfreinforce

import com.cdtec.selfreinforce.core.ReinforcePipeline
import com.cdtec.selfreinforce.core.Signer
import org.gradle.api.DefaultTask
import org.gradle.api.tasks.Internal
import org.gradle.api.tasks.TaskAction
import java.io.File

abstract class SelfReinforceTask : DefaultTask() {

    @get:Internal
    var selfExt: SelfReinforceExtension? = null

    @get:Internal
    var projDir: File? = null

    @TaskAction
    fun run() {
        val ext = selfExt ?: throw IllegalStateException("selfReinforce 扩展未配置")

        // ===== 1. 输入 APK（默认：release 产物目录最新 APK）=====
        val input = if (ext.inputApk.isPresent) {
            ext.inputApk.get().asFile
        } else {
            val dir = File(project.buildDir, "outputs/apk/release")
            val apks = dir.listFiles { f -> f.isFile && f.name.endsWith(".apk") && !f.name.contains("selfprotect") }
            apks?.maxByOrNull { it.lastModified() }
                ?: throw IllegalStateException("未找到 release APK（$dir），请先 assembleRelease 或在 selfReinforce.inputApk 指定")
        }
        require(input.exists()) { "输入 APK 不存在：$input" }

        // ===== 2. 输出 APK（默认：输入同目录 app-selfprotect.apk）=====
        val output = ext.outputApk.orNull?.asFile
            ?: File(input.parentFile, "app-selfprotect.apk")

        // ===== 3. SDK =====
        val sdk = ext.sdkDir.orNull?.let { File(it) } ?: ReinforcePipeline.detectSdkDir(projDir)

        // ===== 4. 签名解析：显式配置 > android signingConfigs(release) > debug keystore =====
        val signing = resolveSigning(project, ext)

        // ===== 5. 加固流水线（含可选多渠道）=====
        ReinforcePipeline.run(
            ReinforcePipeline.Config(
                inputApk = input,
                outputApk = output,
                sdkDir = sdk,
                signing = signing,
                encryptedAssets = ext.encryptedAssets.toList(),
                channels = ext.channels.toList(),
                channelOutputDir = ext.channelOutputDir.orNull?.asFile,
                workDir = File(project.buildDir, "self-reinforce")
            )
        ) { logger.lifecycle(it) }
    }

    /**
     * 签名解析，优先级：
     *  1. 显式配置（storeFile 等 4 项）
     *  2. android extension 的 release signingConfig
     *  3. ~/.android/debug.keystore（androiddebugkey / android）
     */
    private fun resolveSigning(project: org.gradle.api.Project, ext: SelfReinforceExtension): Signer.SigningConfig? {
        // 1) 显式配置
        if (ext.storeFile.isPresent) {
            return Signer.SigningConfig(
                storeFile = ext.storeFile.get().asFile,
                storePassword = ext.storePassword.orNull ?: throw IllegalStateException("配置了 storeFile 时必须配置 storePassword"),
                keyAlias = ext.keyAlias.orNull ?: throw IllegalStateException("配置了 storeFile 时必须配置 keyAlias"),
                keyPassword = ext.keyPassword.orNull ?: throw IllegalStateException("配置了 storeFile 时必须配置 keyPassword")
            )
        }
        // 2) android signingConfigs(release)
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
        // 3) debug keystore
        val debug = File(System.getProperty("user.home"), ".android/debug.keystore")
        if (debug.exists()) {
            logger.lifecycle("[self-reinforce] 使用默认 Android debug 签名：$debug")
            return Signer.SigningConfig(debug, "android", "androiddebugkey", "android")
        }
        logger.warn("[self-reinforce] 未找到任何签名配置，输出对齐后的未签名包")
        return null
    }
}
