package com.selfprotect.reinforce.core

import org.junit.Assert.assertEquals
import org.junit.Test
import java.io.File

class ChannelLoaderTest {

    @Test
    fun `解析txt渠道文件-注释与空行`() {
        val text = """
            # 渠道列表
            oppo

            xiaomi   # 支持行内注释
            huawei
        """.trimIndent()
        assertEquals(listOf("oppo", "xiaomi", "huawei"), ChannelLoader.parse(text))
    }

    @Test
    fun `合并配置渠道与文件渠道并去重保序`() {
        val file = File.createTempFile("channels", ".txt").apply {
            writeText("xiaomi\n# 注释\nhuawei\n")
            deleteOnExit()
        }
        val merged = ChannelLoader.merge(listOf("oppo", "xiaomi"), file)
        assertEquals(listOf("oppo", "xiaomi", "huawei"), merged)
    }

    @Test
    fun `文件不存在时只保留配置渠道`() {
        assertEquals(listOf("oppo"), ChannelLoader.merge(listOf("oppo"), File("/nonexist/ch.txt")))
    }

    @Test
    fun `空配置与空文件返回空列表`() {
        val file = File.createTempFile("channels", ".txt").apply { writeText("# only comment\n\n"); deleteOnExit() }
        assertEquals(emptyList<String>(), ChannelLoader.merge(emptyList(), file))
    }
}
