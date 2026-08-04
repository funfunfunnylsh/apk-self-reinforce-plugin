package com.cdtec.selfreinforce

import com.cdtec.selfreinforce.core.ReinforcePipeline
import com.cdtec.selfreinforce.core.Signer
import java.io.File
import kotlin.system.exitProcess

/**
 * 命令行入口，便于不接入业务工程直接验证加固流水线：
 *
 * ./gradlew :selfReinforceCli \
 *   -PinputApk=/path/app.apk -PoutputApk=/path/out.apk \
 *   [-PsdkDir=/path/sdk] [-Pks=/path/ks -PksPass=xxx -Palias=xxx -PkeyPass=xxx] \
 *   [-PencryptedAssets=maps/,config.json] \
 *   [-Pchannels=oppo,xiaomi] [-PchannelOutputDir=/path/channels]
 */
fun main(args: Array<String>) {
    val props = args.mapNotNull {
        val idx = it.indexOf('=')
        if (idx > 0) it.substring(0, idx) to it.substring(idx + 1) else null
    }.toMap()

    val input = props["inputApk"]?.let(::File)
    val output = props["outputApk"]?.let(::File)
    if (input == null || output == null) {
        System.err.println("用法：selfReinforceCli -PinputApk=... -PoutputApk=... [-PsdkDir=...] [-Pks=... -PksPass=... -Palias=... -PkeyPass=...] [-PencryptedAssets=a,b] [-Pchannels=a,b]")
        exitProcess(1)
    }
    val sdk = props["sdkDir"]?.let(::File) ?: ReinforcePipeline.detectSdkDir()
    val signing = props["ks"]?.let {
        Signer.SigningConfig(
            storeFile = File(it),
            storePassword = props["ksPass"] ?: error("缺少 ksPass"),
            keyAlias = props["alias"] ?: error("缺少 alias"),
            keyPassword = props["keyPass"] ?: error("缺少 keyPass")
        )
    }
    val encryptedAssets = props["encryptedAssets"]?.split(",")?.map { it.trim() }?.filter { it.isNotEmpty() }
        ?: emptyList()
    val channels = props["channels"]?.split(",")?.map { it.trim() }?.filter { it.isNotEmpty() } ?: emptyList()
    val channelOutputDir = props["channelOutputDir"]?.let(::File)

    ReinforcePipeline.run(
        ReinforcePipeline.Config(
            inputApk = input, outputApk = output, sdkDir = sdk,
            signing = signing, encryptedAssets = encryptedAssets,
            channels = channels, channelOutputDir = channelOutputDir
        )
    )
}
