package com.selfprotect.reinforce.core

import java.security.SecureRandom
import javax.crypto.Cipher
import javax.crypto.spec.IvParameterSpec
import javax.crypto.spec.SecretKeySpec

/**
 * 载荷加解密（打包侧）。
 *
 * 与壳模块 resources/shell/com/selfprotect/ShellCrypto.java 使用同一套算法和密钥混淆参数，
 * 两边必须同步修改：
 *  - 算法：AES/CBC/PKCS5Padding
 *  - 文件格式：[16 字节随机 IV][密文]
 *  - 密钥：KEY_PART xor KEY_MASK（拆成两段存放，避免完整密钥以明文常量出现）
 */
object PayloadCrypto {

    private val KEY_PART = byteArrayOf(
        0x3D, 0x51, 0x7A, 0x0E, 0x62, 0x48, 0xC3.toByte(), 0x27,
        0x9B.toByte(), 0x05, 0xE8.toByte(), 0x74, 0x1F, 0xAD.toByte(), 0x56, 0x09
    )

    private val KEY_MASK = byteArrayOf(
        0x59, 0x22, 0x1C, 0x6B, 0x03, 0x2E, 0xA7.toByte(), 0x45,
        (0xF0).toByte(), 0x6A, (0x84).toByte(), 0x10, 0x7C, (0xD8).toByte(), 0x31, 0x65
    )

    fun key(): ByteArray = ByteArray(16) { i -> (KEY_PART[i].toInt() xor KEY_MASK[i].toInt()).toByte() }

    /** 加密：输出 = IV(16B) + AES-CBC 密文 */
    fun encrypt(plain: ByteArray): ByteArray {
        val iv = ByteArray(16).also { SecureRandom().nextBytes(it) }
        val cipher = Cipher.getInstance("AES/CBC/PKCS5Padding")
        cipher.init(Cipher.ENCRYPT_MODE, SecretKeySpec(key(), "AES"), IvParameterSpec(iv))
        return iv + cipher.doFinal(plain)
    }

    /** 解密（主要用于自校验与测试） */
    fun decrypt(data: ByteArray): ByteArray {
        val iv = data.copyOfRange(0, 16)
        val cipher = Cipher.getInstance("AES/CBC/PKCS5Padding")
        cipher.init(Cipher.DECRYPT_MODE, SecretKeySpec(key(), "AES"), IvParameterSpec(iv))
        return cipher.doFinal(data.copyOfRange(16, data.size))
    }
}
