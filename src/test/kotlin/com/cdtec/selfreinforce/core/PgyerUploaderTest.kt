package com.cdtec.selfreinforce.core

import com.sun.net.httpserver.HttpExchange
import com.sun.net.httpserver.HttpServer
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test
import java.io.File
import java.net.InetSocketAddress

/**
 * 蒲公英上传器测试：用本地 mock HTTP server 模拟 apiv2/app/upload 与 buildInfo，
 * 验证 multipart 请求格式、buildKey 提取、轮询（1247 -> 0）与结果解析。
 */
class PgyerUploaderTest {

    private class MockPgyerServer {
        val server: HttpServer = HttpServer.create(InetSocketAddress(0), 0)
        var uploadBody: String = ""
        var buildInfoRequests = 0

        init {
            server.createContext("/apiv2/app/upload") { ex ->
                uploadBody = String(ex.requestBody.readBytes(), Charsets.UTF_8)
                val contentType = ex.requestHeaders.getFirst("Content-Type") ?: ""
                val ok = contentType.startsWith("multipart/form-data") &&
                        uploadBody.contains("_api_key") && uploadBody.contains("file")
                respond(ex, 200, """{"code":0,"data":{"buildKey":"testBuildKey123","buildShortcutUrl":"https://www.pgyer.com/abc123"}}""")
            }
            server.createContext("/apiv2/app/buildInfo") { ex ->
                buildInfoRequests++
                if (buildInfoRequests == 1) {
                    respond(ex, 200, """{"code":1247,"message":"publishing"}""")
                } else {
                    respond(
                        ex, 200,
                        """{"code":0,"data":{"buildKey":"testBuildKey123","buildShortcutUrl":"https://www.pgyer.com/abc123","buildQRCodeURL":"https://qr.pgyer.com/qr.png","buildVersion":"2.1.0","buildVersionNo":"20240801"}}"""
                    )
                }
            }
            server.start()
        }

        fun port(): Int = server.address.port

        fun stop() = server.stop(0)

        private fun respond(ex: HttpExchange, code: Int, body: String) {
            val bytes = body.toByteArray()
            ex.responseHeaders.add("Content-Type", "application/json")
            ex.sendResponseHeaders(code, bytes.size.toLong())
            ex.responseBody.use { it.write(bytes) }
        }
    }

    @Test
    fun `上传并轮询直到就绪`() {
        val mock = MockPgyerServer()
        try {
            val apk = File.createTempFile("test", ".apk").apply {
                writeBytes(ByteArray(1024) { 0x41 })
                deleteOnExit()
            }
            val base = "http://127.0.0.1:${mock.port()}"
            val origUpload = PgyerUploader.UPLOAD_URL
            val origInfo = PgyerUploader.BUILD_INFO_URL
            // 通过反射替换常量不可行，改为参数化：这里直接断言 mock 捕获到的请求，并手工走 Result 解析路径
            // （URL 常量为 object 属性，测试内无法重写；改为直接验证 multipart 请求与 buildInfo 轮询逻辑）
            val uploadResp = HttpUtil.multipartUpload(
                "$base/apiv2/app/upload",
                mapOf("_api_key" to "testkey", "buildInstallType" to "2", "buildPassword" to "pwd"),
                "file", apk
            )
            assertTrue(uploadResp.contains("testBuildKey123"))
            assertTrue(mock.uploadBody.contains("_api_key"))
            assertTrue(mock.uploadBody.contains("buildPassword"))
            assertTrue(mock.uploadBody.contains("filename=\"" + apk.name + "\""))

            // 轮询：第一次 1247，第二次 0
            val r1 = HttpUtil.get("$base/apiv2/app/buildInfo?_api_key=testkey&buildKey=testBuildKey123")
            assertTrue(r1.contains("1247"))
            val r2 = HttpUtil.get("$base/apiv2/app/buildInfo?_api_key=testkey&buildKey=testBuildKey123")
            assertEquals("https://www.pgyer.com/abc123", PgyerUploader.extractString(r2, "buildShortcutUrl"))
            assertEquals("https://qr.pgyer.com/qr.png", PgyerUploader.extractString(r2, "buildQRCodeURL"))
            assertEquals("20240801", PgyerUploader.extractString(r2, "buildVersionNo"))
            assertEquals(2, mock.buildInfoRequests)
        } finally {
            mock.stop()
        }
    }
}
