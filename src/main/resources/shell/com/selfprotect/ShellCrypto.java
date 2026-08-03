package com.selfprotect;

import java.io.ByteArrayOutputStream;
import java.io.InputStream;

import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

/**
 * 壳侧解密。算法与密钥混淆参数必须与打包侧
 * com.cdtec.selfreinforce.core.PayloadCrypto 完全一致：
 * AES/CBC/PKCS5Padding，文件格式 [16 字节 IV][密文]，密钥 = KEY_PART xor KEY_MASK。
 */
final class ShellCrypto {

    private static final byte[] KEY_PART = {
            0x3D, 0x51, 0x7A, 0x0E, 0x62, 0x48, (byte) 0xC3, 0x27,
            (byte) 0x9B, 0x05, (byte) 0xE8, 0x74, 0x1F, (byte) 0xAD, 0x56, 0x09
    };

    private static final byte[] KEY_MASK = {
            0x59, 0x22, 0x1C, 0x6B, 0x03, 0x2E, (byte) 0xA7, 0x45,
            (byte) 0xF0, 0x6A, (byte) 0x84, 0x10, 0x7C, (byte) 0xD8, 0x31, 0x65
    };

    private ShellCrypto() {
    }

    static byte[] decrypt(byte[] data) throws Exception {
        byte[] key = new byte[16];
        for (int i = 0; i < 16; i++) {
            key[i] = (byte) (KEY_PART[i] ^ KEY_MASK[i]);
        }
        byte[] iv = new byte[16];
        System.arraycopy(data, 0, iv, 0, 16);
        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        cipher.init(Cipher.DECRYPT_MODE, new SecretKeySpec(key, "AES"), new IvParameterSpec(iv));
        return cipher.doFinal(data, 16, data.length - 16);
    }

    static byte[] readAll(InputStream in) throws Exception {
        ByteArrayOutputStream bos = new ByteArrayOutputStream();
        byte[] buf = new byte[8192];
        int n;
        while ((n = in.read(buf)) != -1) {
            bos.write(buf, 0, n);
        }
        in.close();
        return bos.toByteArray();
    }
}
