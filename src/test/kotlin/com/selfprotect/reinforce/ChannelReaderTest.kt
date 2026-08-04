package com.selfprotect.reinforce

import com.selfprotect.reinforce.core.ChannelWriter
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Assume.assumeTrue
import org.junit.Test
import java.io.ByteArrayOutputStream
import java.io.File
import java.util.zip.ZipEntry
import java.util.zip.ZipOutputStream

/**
 * 验证插件注入的 ChannelReader 能正确读取 Signing Block 中的渠道。
 * 需要本机 SDK（android.jar）与 javac；缺失时自动跳过（CI 无 SDK 也能过）。
 */
class ChannelReaderTest {

    private fun fakeApk(): ByteArray {
        val bos = ByteArrayOutputStream()
        ZipOutputStream(bos).use { out ->
            listOf("AndroidManifest.xml", "classes.dex").forEach { name ->
                out.putNextEntry(ZipEntry(name))
                out.write("x$name".toByteArray())
                out.closeEntry()
            }
        }
        return bos.toByteArray()
    }

    private fun findAndroidJar(): File? {
        val home = System.getProperty("user.home")
        val candidates = listOf(
            System.getenv("ANDROID_HOME"),
            System.getenv("ANDROID_SDK_ROOT"),
            "$home/Library/Android/sdk",
            "$home/Android/Sdk"
        ).filterNotNull().map(::File)
        for (sdk in candidates) {
            val platforms = File(sdk, "platforms")
            if (!platforms.isDirectory) continue
            val p = platforms.listFiles()
                ?.filter { it.name.startsWith("android-") }
                ?.sortedByDescending { it.name.removePrefix("android-").toIntOrNull() ?: 0 }
                ?.firstOrNull()
            p?.let { return File(it, "android.jar") }
        }
        return null
    }

    @Test
    fun `注入任务已注册`() {
        val project = ProjectBuilder2.newProject()
        project.pluginManager.apply("com.selfprotect.reinforce")
        assertTrue("应注册 generateSelfProtectChannelReader", project.tasks.findByName("generateSelfProtectChannelReader") != null)
    }

    @Test
    fun `ChannelReader 读取写入的渠道`() {
        val androidJar = findAndroidJar()
        assumeTrue("本机无 Android SDK android.jar，跳过", androidJar != null && androidJar!!.exists())
        val jar = androidJar!!

        val apk = ChannelWriter.writeChannel(fakeApk(), "oppo")
        val apkFile = File.createTempFile("channel_test", ".apk").apply { writeBytes(apk) }
        val workDir = File.createTempFile("channel_work", "").apply { delete(); mkdirs() }

        // 1. 从插件资源取出 ChannelReader.java（与插件相同的 ClassLoader 读取方式）
        val src = ChannelReaderTest::class.java.classLoader.getResourceAsStream("channel/ChannelReader.java")!!
        val srcFile = File(workDir, "ChannelReader.java")
        src.use { srcFile.writeBytes(it.readBytes()) }

        // 2. javac 编译（需要 android.jar）
        val classesDir = File(workDir, "classes").apply { mkdirs() }
        val javac = ProcessBuilder(
            "javac", "-cp", jar.absolutePath, "-d", classesDir.absolutePath, srcFile.absolutePath
        ).redirectErrorStream(true).start()
        val javacOut = javac.inputStream.readBytes().toString(Charsets.UTF_8)
        assertEquals("javac 编译失败: $javacOut", 0, javac.waitFor())

        // 3. 写 Main 并运行读取渠道
        val mainFile = File(workDir, "Main.java")
        mainFile.writeText(
            "public class Main { public static void main(String[] a) {" +
                "System.out.println(com.selfprotect.reinforce.ChannelReader.getChannel(a[0])); } }"
        )
        val javac2 = ProcessBuilder(
            "javac", "-cp", classesDir.absolutePath + File.pathSeparator + jar.absolutePath,
            "-d", classesDir.absolutePath, mainFile.absolutePath
        ).redirectErrorStream(true).start()
        assertEquals("Main 编译失败", 0, javac2.waitFor())

        val java = ProcessBuilder(
            "java",
            "-cp", classesDir.absolutePath + File.pathSeparator + jar.absolutePath,
            "Main", apkFile.absolutePath
        ).redirectErrorStream(true).start()
        val out = java.inputStream.readBytes().toString(Charsets.UTF_8).trim()
        assertEquals("应读到写入的渠道", "oppo", out)
    }

    @Test
    fun `无渠道时返回 null`() {
        val androidJar = findAndroidJar()
        assumeTrue("本机无 Android SDK android.jar，跳过", androidJar != null && androidJar!!.exists())
        val jar = androidJar!!

        val apkFile = File.createTempFile("channel_test", ".apk").apply { writeBytes(fakeApk()) }
        val workDir = File.createTempFile("channel_work", "").apply { delete(); mkdirs() }
        val src = ChannelReaderTest::class.java.classLoader.getResourceAsStream("channel/ChannelReader.java")!!
        val srcFile = File(workDir, "ChannelReader.java")
        src.use { srcFile.writeBytes(it.readBytes()) }
        val classesDir = File(workDir, "classes").apply { mkdirs() }
        val javac = ProcessBuilder(
            "javac", "-cp", jar.absolutePath, "-d", classesDir.absolutePath, srcFile.absolutePath
        ).redirectErrorStream(true).start()
        assertEquals(0, javac.waitFor())
        val mainFile = File(workDir, "Main.java")
        mainFile.writeText(
            "public class Main { public static void main(String[] a) {" +
                "System.out.println(String.valueOf(com.selfprotect.reinforce.ChannelReader.getChannel(a[0]))); } }"
        )
        val javac2 = ProcessBuilder(
            "javac", "-cp", classesDir.absolutePath + File.pathSeparator + jar.absolutePath,
            "-d", classesDir.absolutePath, mainFile.absolutePath
        ).redirectErrorStream(true).start()
        assertEquals(0, javac2.waitFor())
        val java = ProcessBuilder(
            "java",
            "-cp", classesDir.absolutePath + File.pathSeparator + jar.absolutePath,
            "Main", apkFile.absolutePath
        ).redirectErrorStream(true).start()
        assertEquals("无渠道应输出 null", "null", java.inputStream.readBytes().toString(Charsets.UTF_8).trim())
    }
}

/** ProjectBuilder 便捷封装（与 SelfReinforcePluginTest 共用） */
object ProjectBuilder2 {
    fun newProject(): org.gradle.api.Project {
        val project = org.gradle.testfixtures.ProjectBuilder.builder().build()
        project.tasks.register("assembleRelease")
        return project
    }
}
