package com.cdtec.selfreinforce.core

import java.io.ByteArrayOutputStream
import java.io.File
import java.io.OutputStream
import java.net.HttpURLConnection
import java.net.URL
import java.net.URLEncoder
import java.nio.charset.StandardCharsets
import java.util.UUID

/**
 * 轻量 HTTP 工具：JSON POST 与 multipart 文件上传（纯 JDK，无外部依赖）。
 */
internal object HttpUtil {

    class HttpException(msg: String, val code: Int = -1, val body: String = "") : RuntimeException(msg)

    /** POST JSON，返回响应体 */
    fun postJson(url: String, json: String, timeoutMs: Int = 30_000): String {
        val conn = (URL(url).openConnection() as HttpURLConnection).apply {
            requestMethod = "POST"
            connectTimeout = timeoutMs
            readTimeout = timeoutMs
            doOutput = true
            setRequestProperty("Content-Type", "application/json; charset=utf-8")
            setRequestProperty("User-Agent", "apk-self-reinforce-plugin")
        }
        conn.outputStream.use { it.write(json.toByteArray(StandardCharsets.UTF_8)) }
        return readResponse(conn)
    }

    /** GET，返回响应体 */
    fun get(url: String, timeoutMs: Int = 30_000): String {
        val conn = (URL(url).openConnection() as HttpURLConnection).apply {
            requestMethod = "GET"
            connectTimeout = timeoutMs
            readTimeout = timeoutMs
            setRequestProperty("User-Agent", "apk-self-reinforce-plugin")
        }
        return readResponse(conn)
    }

    /**
     * multipart/form-data 上传文件。
     * @param fields 表单字段（值字符串）
     * @param fileField 文件字段名（如 "file"）
     */
    fun multipartUpload(
        url: String,
        fields: Map<String, String>,
        fileField: String,
        file: File,
        timeoutMs: Int = 120_000
    ): String {
        val boundary = "----wb-" + UUID.randomUUID()
        val body = buildMultipartBody(fields, fileField, file, boundary)
        val conn = (URL(url).openConnection() as HttpURLConnection).apply {
            requestMethod = "POST"
            connectTimeout = timeoutMs
            readTimeout = timeoutMs
            doOutput = true
            setRequestProperty("Content-Type", "multipart/form-data; boundary=$boundary")
            setRequestProperty("User-Agent", "apk-self-reinforce-plugin")
            setFixedLengthStreamingMode(body.size)
        }
        conn.outputStream.use { it.write(body) }
        return readResponse(conn)
    }

    private fun buildMultipartBody(
        fields: Map<String, String>,
        fileField: String,
        file: File,
        boundary: String
    ): ByteArray {
        val bos = ByteArrayOutputStream()
        val crlf = "\r\n".toByteArray(StandardCharsets.UTF_8)
        val b = "--".toByteArray(StandardCharsets.UTF_8)
        fun partHeader(name: String, filename: String? = null): ByteArray {
            val head = StringBuilder()
            head.append("--").append(boundary).append("\r\n")
            if (filename != null) {
                head.append("Content-Disposition: form-data; name=\"").append(name)
                    .append("\"; filename=\"").append(filename).append("\"\r\n")
                head.append("Content-Type: application/octet-stream\r\n\r\n")
            } else {
                head.append("Content-Disposition: form-data; name=\"").append(name).append("\"\r\n\r\n")
            }
            return head.toString().toByteArray(StandardCharsets.UTF_8)
        }
        fields.forEach { (k, v) ->
            bos.write(partHeader(k))
            bos.write(v.toByteArray(StandardCharsets.UTF_8))
            bos.write(crlf)
        }
        bos.write(partHeader(fileField, file.name))
        bos.write(file.readBytes())
        bos.write(crlf)
        bos.write(b)
        bos.write(boundary.toByteArray(StandardCharsets.UTF_8))
        bos.write("--\r\n".toByteArray(StandardCharsets.UTF_8))
        return bos.toByteArray()
    }

    private fun readResponse(conn: HttpURLConnection): String {
        val code = conn.responseCode
        val stream = if (code in 200..299) conn.inputStream else conn.errorStream
        val body = stream?.bufferedReader(StandardCharsets.UTF_8)?.readText() ?: ""
        if (code !in 200..299) {
            throw HttpException("HTTP $code: ${conn.url}", code, body)
        }
        return body
    }

    /** URL 编码（UTF-8） */
    fun encode(value: String): String = URLEncoder.encode(value, StandardCharsets.UTF_8.toString())
}
