package com.selfprotect.reinforce.core

import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

class DingTalkNotifierTest {

    /** RFC 4231 标准向量：HMAC-SHA256(key="key", data="The quick brown fox jumps over the lazy dog") */
    @Test
    fun `HMAC-SHA256 与标准向量一致`() {
        val b64 = DingTalkNotifier.hmacSha256Base64(
            "key", "The quick brown fox jumps over the lazy dog"
        )
        assertEquals("97yD9DBThCSxMpjmqm+xQ+9NWaFJRhdZl0edvC0aPNg=", b64)
    }

    /** 钉钉加签：HMAC-SHA256(secret, timestamp\nsecret) -> Base64（与 python 交叉验证的值一致） */
    @Test
    fun `钉钉加签算法与交叉验证值一致`() {
        val secret = "SECtestSecretValue123"
        val data = "1613630090490\n$secret"
        assertEquals("Jtrt7t2PdPiiv23tq0mVGd5O7yVKMokDs4oSdrtXfmE=", DingTalkNotifier.hmacSha256Base64(secret, data))
    }

    @Test
    fun `appendSign 生成 timestamp 与 URL 编码的 sign`() {
        val webhook = "https://oapi.dingtalk.com/robot/send?access_token=abc"
        val signed = DingTalkNotifier.appendSign(webhook, "SECtest")
        assertTrue(signed.startsWith(webhook))
        assertTrue(signed.contains("&timestamp="))
        assertTrue(signed.contains("&sign="))
        // sign 为 Base64（可能含 = + /，URL 编码后无 = 与 + 原始字符）
        val signPart = signed.substringAfter("sign=")
        assertTrue(signPart.isNotEmpty())
        assertTrue(!signPart.contains(" "))
    }

    @Test
    fun `buildJson 转义正确`() {
        val json = DingTalkNotifier.buildJson(
            mapOf("msgtype" to "markdown", "n" to 1, "b" to true, "at" to mapOf("isAtAll" to false))
        )
        assertEquals("""{"msgtype":"markdown","n":1,"b":true,"at":{"isAtAll":false}}""", json)
    }

    @Test
    fun `buildJson 处理换行与引号`() {
        val json = DingTalkNotifier.buildJson(mapOf("text" to "line1\nline2 \"quoted\""))
        assertTrue(json.contains("line1\\nline2 \\\"quoted\\\""))
    }
}
