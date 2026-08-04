package com.selfprotect.reinforce.core

import java.net.URLEncoder
import java.nio.charset.StandardCharsets
import javax.crypto.Mac
import javax.crypto.spec.SecretKeySpec

/**
 * 钉钉群机器人通知（markdown 消息格式）。
 *
 * - 发送 markdown 消息到群机器人 webhook
 * - 可选「加签」安全设置：secret 存在时自动附加 timestamp/sign（钉钉官方 HMAC-SHA256 算法）
 * - 成功判定：响应 errcode == 0
 *
 * 配置均为用户提供（不内置任何 key）。
 */
object DingTalkNotifier {

    class DingTalkException(msg: String, val response: String? = null) : RuntimeException(msg)

    /**
     * @param webhook 机器人 webhook URL（含 access_token 查询参数）
     * @param secret  机器人「加签」密钥；null/空 则不签名
     * @param title   卡片标题
     * @param text    markdown 正文
     * @return 响应体
     */
    fun sendMarkdown(webhook: String, secret: String?, title: String, text: String): String {
        val url = if (secret.isNullOrEmpty()) webhook else appendSign(webhook, secret)

        val payload = buildJson(
            mapOf(
                "msgtype" to "markdown",
                "markdown" to mapOf("title" to title, "text" to text),
                "at" to mapOf("atMobiles" to emptyList<String>(), "isAtAll" to false)
            )
        )
        val response = HttpUtil.postJson(url, payload)
        if (!response.contains("\"errcode\":0")) {
            throw DingTalkException("钉钉通知失败：$response", response)
        }
        return response
    }

    /** 钉钉官方加签：HMAC-SHA256(timestamp\nsecret)，Base64，URL 编码，附加到 webhook */
    internal fun appendSign(webhook: String, secret: String): String {
        val timestamp = System.currentTimeMillis()
        val stringToSign = "$timestamp\n$secret"
        val sign = hmacSha256Base64(secret, stringToSign)
        val encoded = URLEncoder.encode(sign, StandardCharsets.UTF_8.toString())
        val separator = if (webhook.contains("?")) "&" else "?"
        return "$webhook${separator}timestamp=$timestamp&sign=$encoded"
    }

    /** HMAC-SHA256(secret, data) -> Base64（用于加签，与钉钉官方示例一致） */
    internal fun hmacSha256Base64(secret: String, data: String): String {
        val mac = Mac.getInstance("HmacSHA256")
        mac.init(SecretKeySpec(secret.toByteArray(StandardCharsets.UTF_8), "HmacSHA256"))
        return java.util.Base64.getEncoder().encodeToString(mac.doFinal(data.toByteArray(StandardCharsets.UTF_8)))
    }

    /** 简易 JSON 序列化（仅需支持字符串/布尔/数字/列表/嵌套 map，值做 JSON 转义） */
    internal fun buildJson(value: Any?): String = when (value) {
        null -> "null"
        is String -> "\"" + value.replace("\\", "\\\\").replace("\"", "\\\"").replace("\n", "\\n").replace("\r", "\\r") + "\""
        is Boolean -> value.toString()
        is Number -> value.toString()
        is Map<*, *> -> value.entries.joinToString(",", "{", "}") { (k, v) -> "${buildJson(k.toString())}:${buildJson(v)}" }
        is List<*> -> value.joinToString(",", "[", "]") { buildJson(it) }
        else -> buildJson(value.toString())
    }
}
