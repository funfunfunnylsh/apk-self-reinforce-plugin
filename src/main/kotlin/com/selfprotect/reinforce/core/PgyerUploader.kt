package com.selfprotect.reinforce.core

import java.io.File

/**
 * 蒲公英（PGYER）上传器（直连蒲公英官方 HTTP API，不依赖 Node CLI）：
 *
 *  1. 上传：POST https://www.pgyer.com/apiv2/app/upload （multipart：_api_key + file + 可选参数）
 *  2. 轮询：GET  https://www.pgyer.com/apiv2/app/buildInfo?_api_key=&buildKey=
 *           code=0 就绪（取下载短链/二维码）；code=1247 发布中（5s × 最多 40 次）
 *
 * 所有 key/描述均为配置项，插件不内置任何密钥。
 */
object PgyerUploader {

    const val UPLOAD_URL = "https://www.pgyer.com/apiv2/app/upload"
    const val BUILD_INFO_URL = "https://www.pgyer.com/apiv2/app/buildInfo"

    data class Config(
        val apiKey: String,
        val installType: String = "2",        // 1=公开安装 2=密码安装 3=邀请安装
        val installPassword: String = "",     // 密码安装时的安装密码
        val updateDescription: String = ""    // 更新说明
    )

    data class Result(
        val buildKey: String,
        val buildShortcutUrl: String,   // 下载短链
        val buildQRCodeURL: String,     // 二维码地址
        val buildVersion: String,       // 版本号
        val buildVersionNo: String      // 构建号
    )

    class PgyerException(msg: String) : RuntimeException(msg)

    /** 上传并轮询直到发布就绪，返回构建信息 */
    fun uploadAndWait(apk: File, config: Config, log: (String) -> Unit = {}): Result {
        val fields = mutableMapOf("_api_key" to config.apiKey, "buildInstallType" to config.installType)
        if (config.installPassword.isNotBlank()) fields["buildPassword"] = config.installPassword
        if (config.updateDescription.isNotBlank()) fields["buildUpdateDescription"] = config.updateDescription

        log("上传蒲公英：${apk.name}（${apk.length() / 1024 / 1024}MB）")
        val uploadResp = HttpUtil.multipartUpload(UPLOAD_URL, fields, "file", apk)
        val buildKey = extractString(uploadResp, "buildKey")
        if (buildKey.isBlank()) {
            throw PgyerException("蒲公英上传失败，响应：$uploadResp")
        }

        // 轮询发布状态
        var lastResp = ""
        for (attempt in 1..40) {
            lastResp = HttpUtil.get(
                "$BUILD_INFO_URL?_api_key=${HttpUtil.encode(config.apiKey)}&buildKey=${HttpUtil.encode(buildKey)}"
            )
            val code = extractString(lastResp, "code")
            when (code) {
                "0" -> {
                    log("蒲公英发布就绪（attempt=$attempt）")
                    return Result(
                        buildKey = buildKey,
                        buildShortcutUrl = extractString(lastResp, "buildShortcutUrl"),
                        buildQRCodeURL = extractString(lastResp, "buildQRCodeURL"),
                        buildVersion = extractString(lastResp, "buildVersion"),
                        buildVersionNo = extractString(lastResp, "buildVersionNo")
                    )
                }
                "1247" -> {
                    log("蒲公英发布中...（$attempt/40）")
                    Thread.sleep(5_000)
                }
                else -> throw PgyerException("蒲公英 buildInfo 异常，code=$code，响应：$lastResp")
            }
        }
        throw PgyerException("蒲公英发布超时（40 次），最后响应：$lastResp")
    }

    /** 极简 JSON 字符串提取（不引入 JSON 依赖；仅提取顶层/嵌套引号值，命中 key 后取首个字符串值） */
    internal fun extractString(json: String, key: String): String {
        // 匹配 "key":"value" 或 "key":value（数字）
        val regex = Regex("\"$key\"\\s*:\\s*\"?([^\"},]*)")
        return regex.find(json)?.groupValues?.get(1)?.trim() ?: ""
    }
}
