package com.selfprotect.reinforce.core

import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotEquals
import org.junit.Assert.assertTrue
import org.junit.Assume.assumeTrue
import org.junit.BeforeClass
import org.junit.Test
import java.io.File
import java.security.MessageDigest
import java.util.zip.Adler32

/**
 * DexMethodExtractor 单元测试：
 * 用 javac + d8 编译真实 class 生成测试 dex（无 SDK 环境自动跳过），验证：
 *  - 抽取后 code_item 区域被回填为最小合法桩（按返回类型）
 *  - 抽取记录回填后与原始 dex 字节完全一致
 *  - 修改后 dex header 的 SHA-1 签名 / adler32 校验和正确
 *  - 规则匹配（整类 / 包前缀 / 精确方法 / 方法名前缀 / 点号形式）
 *  - serialize/parse 往返一致
 */
class DexMethodExtractorTest {

    companion object {
        private var testDex: ByteArray? = null

        private const val SECRET_JAVA = """
package com.test;
public class Secret {
    public Secret() { }
    public static int add(int a, int b) { return a + b + 7; }
    public String greet(String name) { return "hi " + name; }
    public long wide() { return 1234567890123456789L; }
    public void nothing() { int x = 1; if (x > 0) { x++; } }
}
"""

        @BeforeClass
        @JvmStatic
        fun buildDex() {
            val sdk = try {
                ReinforcePipeline.detectSdkDir()
            } catch (t: Throwable) {
                null
            }
            assumeTrue("无 Android SDK，跳过 dex 相关测试", sdk != null)

            val dir = createTempDir("dex-extractor-test")
            val srcDir = File(dir, "src/com/test").apply { mkdirs() }
            val javaFile = File(srcDir, "Secret.java")
            javaFile.writeText(SECRET_JAVA.trimIndent())

            val sdkDir = sdk!!
            val androidJar = File(sdkDir, "platforms").listFiles { f -> File(f, "android.jar").exists() }
                ?.maxByOrNull { it.name }!!.let { File(it, "android.jar") }
            val classesDir = File(dir, "classes").apply { mkdirs() }
            run(listOf("javac", "-classpath", androidJar.absolutePath, "-d", classesDir.absolutePath, javaFile.absolutePath))

            val d8 = ShellDexBuilder.findBuildTool(sdkDir, "d8")
            val dexDir = File(dir, "dex").apply { mkdirs() }
            val classFiles = classesDir.walkTopDown().filter { it.extension == "class" }.map { it.absolutePath }.toList()
            run(listOf("sh", d8.absolutePath, "--lib", androidJar.absolutePath, "--min-api", "21", "--output", dexDir.absolutePath) + classFiles)
            testDex = File(dexDir, "classes.dex").readBytes()
        }

        private fun run(cmd: List<String>) {
            val p = ProcessBuilder(cmd).redirectErrorStream(true).start()
            val out = p.inputStream.bufferedReader().readText()
            check(p.waitFor() == 0) { "命令失败: ${cmd.joinToString(" ")}\n$out" }
        }

        private fun u16(b: ByteArray, off: Int) = (b[off].toInt() and 0xFF) or ((b[off + 1].toInt() and 0xFF) shl 8)
        private fun u32(b: ByteArray, off: Int) =
            (b[off].toLong() and 0xFF) or ((b[off + 1].toLong() and 0xFF) shl 8) or
                    ((b[off + 2].toLong() and 0xFF) shl 16) or ((b[off + 3].toLong() and 0xFF) shl 24)
    }

    private fun dex(): ByteArray = testDex ?: throw org.junit.AssumptionViolatedException("no dex")

    @Test
    fun `整类抽取 - 构造器跳过 其余方法全部抽空`() {
        val result = DexMethodExtractor.extract(dex(), 0, listOf("Lcom/test/Secret;"))
        // Secret 有 5 个方法：<init>(跳过) + add/greet/wide/nothing
        assertEquals(4, result.methods.size)
        val names = result.methods.map { it.display }
        assertTrue(names.contains("Lcom/test/Secret;->add"))
        assertTrue(names.contains("Lcom/test/Secret;->greet"))
        assertTrue(names.contains("Lcom/test/Secret;->wide"))
        assertTrue(names.contains("Lcom/test/Secret;->nothing"))
    }

    @Test
    fun `抽取后回填的桩符合返回类型`() {
        val result = DexMethodExtractor.extract(dex(), 0, listOf("Lcom/test/Secret;"))
        result.methods.forEach { m ->
            val off = m.codeOff
            // 桩头：tries_size=0, debug_info_off=0
            assertEquals(0, u16(result.dex, off + 6))
            assertEquals(0L, u32(result.dex, off + 8))
            val insnsSize = u32(result.dex, off + 12).toInt()
            when {
                m.display.endsWith("->nothing") -> {
                    assertEquals(1, insnsSize)
                    assertEquals(0x000E, u16(result.dex, off + 16)) // return-void
                }
                m.display.endsWith("->wide") -> {
                    assertEquals(2, insnsSize)
                    assertEquals(0x1200, u16(result.dex, off + 16)) // const/4 v0,#0
                    assertEquals(0x1000, u16(result.dex, off + 18)) // return-wide v0
                }
                m.display.endsWith("->greet") -> {
                    assertEquals(2, insnsSize)
                    assertEquals(0x1200, u16(result.dex, off + 16))
                    assertEquals(0x1100, u16(result.dex, off + 18)) // return-object v0
                }
                m.display.endsWith("->add") -> {
                    assertEquals(2, insnsSize)
                    assertEquals(0x1200, u16(result.dex, off + 16))
                    assertEquals(0x0F00, u16(result.dex, off + 18)) // return v0
                }
            }
            // 原 code_item 尾部区域必须清零（不残留原始指令）
            for (i in m.code.indices) {
                if (i < 16 + insnsSize * 2) continue // 桩自身区域
                assertEquals("offset $i of ${m.display} 应清零", 0, result.dex[off + i].toInt())
            }
        }
    }

    @Test
    fun `回填后与原始 dex 字节完全一致`() {
        val result = DexMethodExtractor.extract(dex(), 0, listOf("Lcom/test/Secret;"))
        val restored = result.dex.copyOf()
        result.methods.forEach { m ->
            System.arraycopy(m.code, 0, restored, m.codeOff, m.code.size)
        }
        // header 签名/校验和区域除外（抽取后重算过），回填后剩余部分应一致
        assertArrayEquals(dex().copyOfRange(32, dex().size), restored.copyOfRange(32, restored.size))
    }

    @Test
    fun `抽取后 dex header 签名与校验和正确`() {
        val result = DexMethodExtractor.extract(dex(), 0, listOf("Lcom/test/Secret;"))
        val d = result.dex
        val sha = MessageDigest.getInstance("SHA-1").digest(d.copyOfRange(32, d.size))
        assertArrayEquals(sha, d.copyOfRange(12, 32))
        val adler = Adler32().apply { update(d, 12, d.size - 12) }.value
        assertEquals(adler and 0xFFFFFFFFL, u32(d, 8))
    }

    @Test
    fun `规则匹配 - 点号形式与包前缀`() {
        val dotForm = DexMethodExtractor.extract(dex(), 0, listOf("com.test.Secret"))
        assertEquals(4, dotForm.methods.size)

        val pkgPrefix = DexMethodExtractor.extract(dex(), 0, listOf("com.test.*"))
        assertEquals(4, pkgPrefix.methods.size)

        val descPrefix = DexMethodExtractor.extract(dex(), 0, listOf("Lcom/test/*"))
        assertEquals(4, descPrefix.methods.size)

        val noMatch = DexMethodExtractor.extract(dex(), 0, listOf("Lcom/other/*"))
        assertEquals(0, noMatch.methods.size)
        // 未命中时 dex 不应被修改
        assertArrayEquals(dex(), noMatch.dex)
    }

    @Test
    fun `规则匹配 - 精确方法与方法名前缀`() {
        val exact = DexMethodExtractor.extract(dex(), 0, listOf("Lcom/test/Secret;->add"))
        assertEquals(1, exact.methods.size)
        assertEquals("Lcom/test/Secret;->add", exact.methods[0].display)

        val prefix = DexMethodExtractor.extract(dex(), 0, listOf("Lcom/test/Secret;->gr*"))
        assertEquals(1, prefix.methods.size)
        assertEquals("Lcom/test/Secret;->greet", prefix.methods[0].display)
    }

    @Test
    fun `serialize 与 parse 往返一致`() {
        val result = DexMethodExtractor.extract(dex(), 0, listOf("Lcom/test/Secret;"))
        val blob = DexMethodExtractor.serialize(result.methods)
        val parsed = DexMethodExtractor.parse(blob)
        assertEquals(result.methods.size, parsed.size)
        result.methods.zip(parsed).forEach { (a, b) ->
            assertEquals(a.dexIndex, b.dexIndex)
            assertEquals(a.codeOff, b.codeOff)
            assertArrayEquals(a.code, b.code)
        }
    }

    @Test
    fun `未命中规则时原 dex 不被修改`() {
        val result = DexMethodExtractor.extract(dex(), 0, listOf("Lnot/exist/Clazz;"))
        assertEquals(0, result.methods.size)
        assertArrayEquals(dex(), result.dex)
    }

    @Test
    fun `桩与原始字节确实不同（防自欺）`() {
        val result = DexMethodExtractor.extract(dex(), 0, listOf("Lcom/test/Secret;"))
        result.methods.forEach { m ->
            val patched = result.dex.copyOfRange(m.codeOff, m.codeOff + m.code.size)
            assertNotEquals(m.code.toList(), patched.toList())
        }
    }
}
