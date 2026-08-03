package com.cdtec.selfreinforce

import org.gradle.api.Plugin
import org.gradle.api.Project
import org.gradle.api.provider.Property
import java.io.File

/**
 * 自研 APK 加固插件（不依赖任何第三方加固二进制）。
 *
 * 用法（业务 app 模块中）：
 * ```
 * plugins { id("com.cdtec.plugin.apk-self-reinforce") }
 * selfReinforce {
 *     inputApk.set(layout.buildDirectory.file("outputs/apk/release/app-release.apk"))
 *     outputApk.set(layout.buildDirectory.file("outputs/apk/release/app-release-selfprotect.apk"))
 *     sdkDir.set("/Users/xxx/Library/Android/sdk")   // 可选，默认自动探测
 *     // 以下不配置则只输出对齐后的未签名包
 *     storeFile.set(file("xxx.keystore"))
 *     storePassword.set("...")
 *     keyAlias.set("...")
 *     keyPassword.set("...")
 * }
 * ```
 * 执行：./gradlew selfReinforceApk
 */
abstract class SelfReinforceExtension(project: Project) {
    val inputApk = project.objects.fileProperty()
    val outputApk = project.objects.fileProperty()
    val sdkDir: Property<String> = project.objects.property(String::class.java)
    val storeFile = project.objects.fileProperty()
    val storePassword: Property<String> = project.objects.property(String::class.java)
    val keyAlias: Property<String> = project.objects.property(String::class.java)
    val keyPassword: Property<String> = project.objects.property(String::class.java)

    /** 需要加密的 assets 路径规则（前缀/精确匹配，如 "maps/"、"config.json"），空则不加密 */
    val encryptedAssets: MutableList<String> = mutableListOf()
}

class SelfReinforcePlugin : Plugin<Project> {
    override fun apply(project: Project) {
        val ext = project.extensions.create("selfReinforce", SelfReinforceExtension::class.java, project)
        val provider = project.tasks.register("selfReinforceApk", SelfReinforceTask::class.java)
        provider.configure {
            group = "reinforce"
            description = "自研加固：DEX 加密 + 壳 Application + 重签名"
            selfExt = ext
            projDir = project.projectDir
        }
    }
}
