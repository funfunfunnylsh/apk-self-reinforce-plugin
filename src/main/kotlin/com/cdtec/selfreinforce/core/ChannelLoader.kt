package com.cdtec.selfreinforce.core

import java.io.File

/**
 * 多渠道加载器：合并「配置项渠道」与「txt 渠道文件」。
 * txt 规则：每行一个渠道名；`#` 开头为注释；忽略空行；可去重（保持首次出现顺序）。
 */
object ChannelLoader {

    /** 解析渠道文件内容（支持整行/行内 # 注释、空行） */
    fun parse(text: String): List<String> =
        text.lineSequence()
            .map { it.substringBefore('#').trim() } // 支持行内注释
            .filter { it.isNotEmpty() }
            .toList()

    /** 合并配置渠道与文件渠道并去重（保序） */
    fun merge(configured: List<String>, file: File?): List<String> {
        val fromFile = file?.takeIf { it.exists() }?.readText(Charsets.UTF_8)?.let(::parse) ?: emptyList()
        val seen = LinkedHashSet<String>()
        (configured + fromFile).forEach { if (it.isNotBlank()) seen.add(it.trim()) }
        return seen.toList()
    }
}
