package com.selfprotect.reinforce.core

import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class PayloadCryptoTest {

    @Test
    fun `加密解密往返一致`() {
        val plain = "hello self-reinforce 自研加固 🚀".toByteArray(Charsets.UTF_8)
        val encrypted = PayloadCrypto.encrypt(plain)
        // 密文 = IV(16B) + AES-CBC 密文（PKCS5 padding 后为 16 的倍数）
        assertTrue("密文应大于明文", encrypted.size > plain.size)
        assertEquals(0, (encrypted.size - 16) % 16)
        assertFalse("密文不应包含明文", String(encrypted, Charsets.UTF_8).contains("hello"))
        assertArrayEquals(plain, PayloadCrypto.decrypt(encrypted))
    }

    @Test
    fun `相同明文两次加密密文不同(随机IV)`() {
        val plain = byteArrayOf(1, 2, 3, 4, 5)
        assertFalse(PayloadCrypto.encrypt(plain).contentEquals(PayloadCrypto.encrypt(plain)))
    }

    @Test
    fun `密钥长度16字节`() {
        assertEquals(16, PayloadCrypto.key().size)
    }
}
