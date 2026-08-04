package com.selfprotect.reinforce

import org.gradle.api.Plugin
import org.gradle.api.Project
import org.gradle.api.provider.Property
import java.io.File

/**
 * 自研 APK 加固插件（不依赖任何第三方加固二进制）。
 *
 * 全部配置项均有默认值：
 *  - inputApk  : 默认取 build/outputs/apk/release 下最新 APK
 *  - outputApk : 默认 inputApk 同目录 app-selfprotect.apk
 *  - 签名      : 优先级 = 显式配置 > android signingConfigs(release) > ~/.android/debug.keystore
 *  - channels  : 配置后加固完自动产出多渠道包（写入 Signing Block，无需重签名）
 *
 * 用法（业务 app 模块中）：
 * ```
 * plugins { id("com.selfprotect.reinforce") }
 * selfReinforce {
 *     inputApk.set(...)            // 可选
 *     outputApk.set(...)           // 可选
 *     sdkDir.set("...")            // 可选，默认自动探测
 *     storeFile.set(file("xxx.keystore")); storePassword.set("...")  // 可选
 *     keyAlias.set("..."); keyPassword.set("...")                    // 可选
 *     encryptedAssets.add("private/") // 可选：assets 加密规则
 *     channels.addAll(listOf("oppo", "xiaomi", "huawei"))  // 可选：多渠道
 *     channelOutputDir.set(...)    // 可选，默认 outputApk 同目录 channels/
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

    /** 需要加密的 assets 路径规则（前缀/精确匹配，如 "private/"、"config.bin"），空则不加密 */
    val encryptedAssets: MutableList<String> = mutableListOf()

    /** 多渠道列表（如 oppo/xiaomi/huawei），空则不产渠道包 */
    val channels: MutableList<String> = mutableListOf()

    /** 多渠道 txt 文件（可选，每行一个渠道，# 注释；与 channels 配置合并去重） */
    val channelFile = project.objects.fileProperty()

    /** 渠道包输出目录，默认 outputApk 同目录 channels/ */
    val channelOutputDir = project.objects.directoryProperty()

    // ===== 蒲公英上传（可选，配置 pgyerApiKey 即启用）=====
    val pgyerApiKey: Property<String> = project.objects.property(String::class.java)
    val pgyerInstallType: Property<String> = project.objects.property(String::class.java) // 1公开 2密码 3邀请
    val pgyerInstallPassword: Property<String> = project.objects.property(String::class.java)
    val pgyerUpdateDescription: Property<String> = project.objects.property(String::class.java)
    /** true 时所有渠道包也上传蒲公英（默认只传主包） */
    val pgyerUploadAllChannels: Property<Boolean> = project.objects.property(Boolean::class.java)

    // ===== 钉钉群机器人通知（可选，配置 dingTalkWebhook 即启用）=====
    val dingTalkWebhook: Property<String> = project.objects.property(String::class.java)
    /** 机器人「加签」密钥（可选，配置后自动附加 timestamp/sign） */
    val dingTalkSecret: Property<String> = project.objects.property(String::class.java)
    /** 消息标题关键字（钉钉机器人安全设置的关键字，用于构建消息标题） */
    val dingTalkKeyword: Property<String> = project.objects.property(String::class.java)
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
