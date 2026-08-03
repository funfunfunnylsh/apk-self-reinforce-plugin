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
        require(ext.inputApk.isPresent) { "请配置 selfReinforce.inputApk" }
        val input = ext.inputApk.get().asFile
        val output = ext.outputApk.orNull?.asFile
            ?: File(input.parentFile, input.nameWithoutExtension + "_selfprotect.apk")
        val sdk = ext.sdkDir.orNull?.let { File(it) } ?: ReinforcePipeline.detectSdkDir(projDir)

        val signing = if (ext.storeFile.isPresent) {
            Signer.SigningConfig(
                storeFile = ext.storeFile.get().asFile,
                storePassword = ext.storePassword.orNull
                    ?: throw IllegalStateException("配置了 storeFile 时必须配置 storePassword"),
                keyAlias = ext.keyAlias.orNull
                    ?: throw IllegalStateException("配置了 storeFile 时必须配置 keyAlias"),
                keyPassword = ext.keyPassword.orNull
                    ?: throw IllegalStateException("配置了 storeFile 时必须配置 keyPassword")
            )
        } else {
            logger.lifecycle("[self-reinforce] 未配置签名信息，仅输出对齐后的未签名包")
            null
        }

        ReinforcePipeline.run(
            ReinforcePipeline.Config(
                inputApk = input,
                outputApk = output,
                sdkDir = sdk,
                signing = signing,
                encryptedAssets = ext.encryptedAssets.toList(),
                workDir = File(project.buildDir, "self-reinforce")
            )
        ) { logger.lifecycle(it) }
    }
}
