package com.selfprotect.reinforce.core

import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * AxmlEditor 回归测试：用 aapt2 生成的二进制 AndroidManifest.xml 样本
 * 验证入口替换 + 幂等性，防止 AXML 解析/字符串池重建回归。
 */
class AxmlEditorTest {

    private fun sampleManifest(): ByteArray =
        javaClass.classLoader.getResourceAsStream("sample_AndroidManifest.xml")!!.readBytes()

    private fun manifestWithoutAppName(): ByteArray =
        javaClass.classLoader.getResourceAsStream("sample_manifest_no_name.xml")!!.readBytes()

    @Test
    fun `替换application入口并返回原值`() {
        val sample = sampleManifest()
        val (patched, oldName) = AxmlEditor.replaceApplicationName(sample, "com.selfprotect.StubApplication")
        assertEquals("com.example.demo.DemoApp", oldName)
        assertTrue("替换结果应非空", patched.isNotEmpty())
        // 幂等：二次替换能再次解析并返回第一次替换的结果
        val (patched2, oldName2) = AxmlEditor.replaceApplicationName(patched, "com.selfprotect.StubApplication")
        assertEquals("com.selfprotect.StubApplication", oldName2)
        assertEquals(patched.size, patched2.size)
    }

    @Test
    fun `AppComponentFactory被替换为框架默认`() {
        val (patched, _) = AxmlEditor.replaceApplicationName(sampleManifest(), "com.selfprotect.StubApplication")
        // 字符串池为 UTF-8 或 UTF-16LE 编码，按两种编码的字节序列搜索
        val target = "android.app.AppComponentFactory"
        val inUtf8 = patched.containsSequence(target.toByteArray(Charsets.UTF_8))
        val inUtf16 = patched.containsSequence(target.toByteArray(Charsets.UTF_16LE))
        assertTrue("应包含 android.app.AppComponentFactory", inUtf8 || inUtf16)
    }

    @Test
    fun `无application-name时插入name属性`() {
        // 样本 manifest 的 <application> 没有 android:name（默认 android.app.Application）
        val (patched, oldName) = AxmlEditor.replaceApplicationName(manifestWithoutAppName(), "com.selfprotect.StubApplication")
        assertEquals("android.app.Application", oldName)
        // 幂等：二次替换能再次解析（证明插入的属性结构合法）
        val (patched2, oldName2) = AxmlEditor.replaceApplicationName(patched, "com.selfprotect.StubApplication")
        assertEquals("com.selfprotect.StubApplication", oldName2)
    }

    private fun ByteArray.containsSequence(seq: ByteArray): Boolean {
        if (seq.isEmpty() || seq.size > size) return false
        outer@ for (i in 0..size - seq.size) {
            for (j in seq.indices) {
                if (this[i + j] != seq[j]) continue@outer
            }
            return true
        }
        return false
    }
}
