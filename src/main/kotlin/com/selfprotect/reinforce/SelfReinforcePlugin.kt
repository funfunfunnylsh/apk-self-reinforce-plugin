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
 *     hookToAssembleRelease.set(true)  // 可选：assembleRelease 跑完自动加固
 * }
 * ```
 * 执行（一条命令，自动先打 release 包再加固+重签）：
 *   ./gradlew :app:selfReinforceApk
 * 若开启 hookToAssembleRelease，则 ./gradlew :app:assembleRelease 也会自动追加加固。
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

    // ===== 打包阶段集成 =====
    /** true（默认）：selfReinforceApk 自动依赖 assembleRelease，一条命令完成 打包+加固+重签 */
    val autoBuildRelease: Property<Boolean> = project.objects.property(Boolean::class.java)
    /** true：把加固 hook 到 assembleRelease 末尾，直接跑 assembleRelease 也会自动加固（默认 false） */
    val hookToAssembleRelease: Property<Boolean> = project.objects.property(Boolean::class.java)
}

class SelfReinforcePlugin : Plugin<Project> {
    override fun apply(project: Project) {
        val ext = project.extensions.create("selfReinforce", SelfReinforceExtension::class.java, project)
        val provider = project.tasks.register("selfReinforceApk", SelfReinforceTask::class.java)
        provider.configure {
            group = "reinforce"
            description = "自研加固：DEX 加密 + 壳 Application + 重签名（默认自动依赖 assembleRelease，一条命令全链路）"
            selfExt = ext
            projDir = project.projectDir
        }

        // 一条命令：selfReinforceApk 自动先执行 assembleRelease（懒依赖，assembleRelease 不存在时无害）
        // 用 TaskCollection 依赖保证 AGP 未 apply / 任务尚未注册也不报错
        provider.configure {
            dependsOn(project.tasks.matching { it.name == "assembleRelease" })
        }

        // 可选：把加固 hook 到 assembleRelease 末尾（assembleRelease 跑完自动追加加固）
        project.afterEvaluate {
            if (ext.hookToAssembleRelease.getOrElse(false)) {
                project.tasks.matching { it.name == "assembleRelease" }.configureEach {
                    finalizedBy(provider)
                }
                project.logger.lifecycle("[self-reinforce] hookToAssembleRelease=true：assembleRelease 完成后自动执行 selfReinforceApk")
            }
        }

        // 向 Android app 注入渠道读取类（ChannelReader），业务代码直接调用读取多渠道信息
        injectChannelReader(project)
    }

    /**
     * 生成 ChannelReader.java 到 build/generated/selfprotect/java 并加入 android main sourceSets。
     * 业务代码即可直接使用：ChannelReader.getChannel(context)
     */
    private fun injectChannelReader(project: Project) {
        val outDir = project.layout.buildDirectory.dir("generated/selfprotect/java")
        val genTask = project.tasks.register("generateSelfProtectChannelReader") {
            group = "reinforce"
            description = "生成 ChannelReader.java（运行时读取多渠道信息）"
            outputs.dir(outDir)
            doLast {
                val src = javaClass.getResourceAsStream("/channel/ChannelReader.java")
                    ?: throw IllegalStateException("插件资源缺少 channel/ChannelReader.java")
                val target = File(outDir.get().asFile, "com/selfprotect/reinforce/ChannelReader.java")
                target.parentFile.mkdirs()
                src.use { target.writeBytes(it.readBytes()) }
            }
        }
        project.afterEvaluate {
            val androidExt = project.extensions.findByName("android")
            if (androidExt is com.android.build.api.dsl.ApplicationExtension) {
                androidExt.sourceSets.getByName("main").java.srcDir(outDir)
                project.tasks.matching { it.name == "preBuild" }.configureEach {
                    dependsOn(genTask)
                }
                project.logger.lifecycle("[self-reinforce] 已注入渠道读取类：com.selfprotect.reinforce.ChannelReader")
            }
        }
    }
}
