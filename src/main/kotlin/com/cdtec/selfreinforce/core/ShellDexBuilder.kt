package com.cdtec.selfreinforce.core

import java.io.File

/**
 * 壳 DEX 构建器：把 resources/shell 下的壳 Java 源码编译成 classes.dex。
 *
 * 流程：javac（-classpath android.jar）→ d8（--min-api 21）
 * 所需工具全部来自本机 Android SDK：
 *  - platforms/android-XX/android.jar（取最高版本）
 *  - build-tools/XX/d8
 */
object ShellDexBuilder {

    private val SHELL_SOURCES = listOf(
        "shell/com/selfprotect/StubApplication.java",
        "shell/com/selfprotect/ShellCrypto.java",
        "shell/com/selfprotect/SecureAssets.java"
    )

    class BuildException(msg: String) : RuntimeException(msg)

    /** @return 壳 classes.dex 字节 */
    fun buildShellDex(sdkDir: File, workDir: File): ByteArray {
        val androidJar = findAndroidJar(sdkDir)
        val d8 = findBuildTool(sdkDir, "d8")

        val srcDir = File(workDir, "shell-src").apply { mkdirs() }
        val classesDir = File(workDir, "shell-classes").apply { mkdirs() }
        val dexDir = File(workDir, "shell-dex").apply { mkdirs() }

        // 1. 从插件资源中释放壳源码
        val javaFiles = SHELL_SOURCES.map { resPath ->
            val target = File(srcDir, resPath.substringAfter("shell/"))
            target.parentFile.mkdirs()
            val stream = ShellDexBuilder::class.java.classLoader.getResourceAsStream(resPath)
                ?: throw BuildException("插件资源缺失：$resPath")
            target.writeBytes(stream.readBytes())
            target
        }

        // 2. javac 编译
        run(
            listOf(
                "javac", "-source", "8", "-target", "8",
                "-encoding", "UTF-8",
                "-classpath", androidJar.absolutePath,
                "-d", classesDir.absolutePath
            ) + javaFiles.map { it.absolutePath },
            errorHint = "壳源码 javac 编译失败"
        )

        // 3. d8 转 dex
        val classFiles = classesDir.walkTopDown().filter { it.extension == "class" }.map { it.absolutePath }.toList()
        if (classFiles.isEmpty()) throw BuildException("javac 未产出任何 class 文件")
        run(
            listOf(
                "sh", d8.absolutePath,
                "--lib", androidJar.absolutePath,
                "--min-api", "21",
                "--output", dexDir.absolutePath
            ) + classFiles,
            errorHint = "d8 转换失败"
        )

        val dex = File(dexDir, "classes.dex")
        if (!dex.exists()) throw BuildException("d8 未产出 classes.dex")
        return dex.readBytes()
    }

    private fun findAndroidJar(sdkDir: File): File {
        val platforms = File(sdkDir, "platforms")
        val dir = platforms.listFiles { f -> f.isDirectory && File(f, "android.jar").exists() }
            ?.maxByOrNull { it.name.removePrefix("android-").toIntOrNull() ?: 0 }
            ?: throw BuildException("未在 ${platforms} 找到任何 android.jar")
        return File(dir, "android.jar")
    }

    internal fun findBuildTool(sdkDir: File, tool: String): File {
        val buildTools = File(sdkDir, "build-tools")
        val candidates = buildTools.listFiles { f -> f.isDirectory }
            ?.sortedByDescending { it.name }
            ?: throw BuildException("未找到 build-tools 目录：$buildTools")
        for (dir in candidates) {
            val f = File(dir, tool)
            if (f.exists()) return f
        }
        throw BuildException("build-tools 中未找到工具：$tool")
    }

    /** 在 build-tools 中查找 lib 子目录下的 jar（如 apksigner.jar） */
    internal fun findBuildToolLib(sdkDir: File, jarName: String): File {
        val buildTools = File(sdkDir, "build-tools")
        val candidates = buildTools.listFiles { f -> f.isDirectory }?.sortedByDescending { it.name }
            ?: throw BuildException("未找到 build-tools 目录：$buildTools")
        for (dir in candidates) {
            val f = File(dir, "lib/$jarName")
            if (f.exists()) return f
        }
        throw BuildException("build-tools 中未找到：lib/$jarName")
    }

    private fun run(cmd: List<String>, errorHint: String) {
        val process = ProcessBuilder(cmd).redirectErrorStream(true).start()
        val output = process.inputStream.bufferedReader().readText()
        val code = process.waitFor()
        if (code != 0) {
            throw BuildException("$errorHint (exit=$code)\n命令：${cmd.joinToString(" ")}\n输出：$output")
        }
    }
}
