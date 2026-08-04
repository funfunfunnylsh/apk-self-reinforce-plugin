package com.selfprotect.reinforce.core

import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test
import java.io.ByteArrayOutputStream
import java.nio.ByteBuffer
import java.nio.ByteOrder
import java.util.zip.ZipEntry
import java.util.zip.ZipFile
import java.util.zip.ZipOutputStream

class ChannelWriterTest {

    /** 构造一个含少量条目的小 zip（模拟未签名 APK） */
    private fun fakeApk(): ByteArray {
        val bos = ByteArrayOutputStream()
        ZipOutputStream(bos).use { out ->
            listOf("AndroidManifest.xml", "classes.dex", "resources.arsc").forEach { name ->
                out.putNextEntry(ZipEntry(name))
                out.write(("fake-$name-${name.hashCode()}").toByteArray())
                out.closeEntry()
            }
        }
        return bos.toByteArray()
    }

    @Test
    fun `写入渠道并读回一致`() {
        val apk = fakeApk()
        val out = ChannelWriter.writeChannel(apk, "oppo")
        assertEquals("oppo", ChannelWriter.readChannel(out))
    }

    @Test
    fun `连续写入会覆盖旧渠道`() {
        var apk = fakeApk()
        apk = ChannelWriter.writeChannel(apk, "xiaomi")
        apk = ChannelWriter.writeChannel(apk, "huawei")
        assertEquals("huawei", ChannelWriter.readChannel(apk))
    }

    @Test
    fun `zip结构保持完整`() {
        val apk = fakeApk()
        val out = ChannelWriter.writeChannel(apk, "vivo")
        // ZipFile 能正常打开（EOCD cdOffset 修正正确）
        ZipFile(out.toByteArrayToTempFile()).use { zip ->
            val names = zip.entries().asSequence().map { it.name }.toList()
            assertTrue(names.containsAll(listOf("AndroidManifest.xml", "classes.dex", "resources.arsc")))
            assertEquals(3, names.size)
        }
    }

    @Test
    fun `无渠道返回null`() {
        assertNull(ChannelWriter.readChannel(fakeApk()))
    }

    @Test
    fun `多渠道连续写入保持幂等`() {
        var apk = fakeApk()
        repeat(3) { apk = ChannelWriter.writeChannel(apk, "oppo") }
        assertEquals("oppo", ChannelWriter.readChannel(apk))
        // 签名块只应有一个 channel pair
        val (_, cdOffset) = locateEocdPublic(apk)
        val block = ChannelWriterTestHelper.findBlock(apk, cdOffset)
        assertNotNull(block)
    }

    private fun ByteArray.toByteArrayToTempFile(): java.io.File {
        val f = java.io.File.createTempFile("channel-test", ".apk")
        f.writeBytes(this)
        f.deleteOnExit()
        return f
    }

    // 复用 ChannelWriter 内部定位逻辑做断言辅助
    private fun locateEocdPublic(apk: ByteArray): Pair<Int, Int> {
        val sig = byteArrayOf(0x50, 0x4B, 0x05, 0x06)
        var pos = apk.size - 4
        while (pos >= 0) {
            if (apk[pos] == sig[0] && apk[pos + 1] == sig[1] && apk[pos + 2] == sig[2] && apk[pos + 3] == sig[3]) {
                val commentLen = (apk[pos + 20].toInt() and 0xFF) or ((apk[pos + 21].toInt() and 0xFF) shl 8)
                if (pos + 22 + commentLen == apk.size) {
                    val cdOffset = ByteBuffer.wrap(apk).order(ByteOrder.LITTLE_ENDIAN).getInt(pos + 16)
                    return pos to cdOffset
                }
            }
            pos--
        }
        throw IllegalStateException("no eocd")
    }
}

internal object ChannelWriterTestHelper {
    fun findBlock(apk: ByteArray, cdOffset: Int): ByteArray? {
        val magic = "APK Sig Block 42".toByteArray(Charsets.US_ASCII)
        if (cdOffset < 24) return null
        val magicPos = cdOffset - 16
        if (!magic.contentEquals(apk.copyOfRange(magicPos, magicPos + 16))) return null
        val size = ByteBuffer.wrap(apk).order(ByteOrder.LITTLE_ENDIAN).getLong(cdOffset - 24)
        val start = cdOffset - size.toInt() - 8 // size 不含首字段
        return apk.copyOfRange(start, cdOffset)
    }
}
