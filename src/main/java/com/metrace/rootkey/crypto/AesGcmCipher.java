package com.metrace.rootkey.crypto;

import com.metrace.rootkey.RootKeyException;

import javax.crypto.Cipher;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.security.SecureRandom;

/**
 * AES-256-GCM 认证加密。
 *
 * <p>密文格式（字节布局，向前兼容的稳定格式）：</p>
 * <pre>
 *   偏移  长度     含义
 *   0     2       魔数 'R','K' (0x52 0x4B)
 *   2     1       格式版本 0x01
 *   3     12      随机 IV (96-bit)
 *   15    n+16    密文 + GCM 认证标签 (128-bit)
 * </pre>
 * <p>加密每次使用随机 IV（同一明文每次密文不同，属正确语义）；
 * 解密对错误密钥、被篡改的密文均会失败（认证标签校验）。</p>
 */
public final class AesGcmCipher {

    private static final byte[] MAGIC = {0x52, 0x4B};
    private static final byte FORMAT_VERSION = 0x01;
    private static final int IV_LENGTH = 12;
    private static final int TAG_LENGTH_BYTES = 16;
    private static final int TAG_LENGTH_BITS = 128;
    private static final int HEADER_LENGTH = 3 + IV_LENGTH;

    private final SecureRandom random;

    public AesGcmCipher() {
        this(new SecureRandom());
    }

    public AesGcmCipher(SecureRandom random) {
        this.random = random;
    }

    /** 加密（根密钥 32 字节，输出 = 头 || IV || 密文+Tag） */
    public byte[] encrypt(byte[] key, byte[] plaintext) {
        if (key == null || key.length != 32) {
            throw new RootKeyException("AES-256 需要 32 字节根密钥，实际 " + (key == null ? 0 : key.length));
        }
        try {
            byte[] iv = new byte[IV_LENGTH];
            random.nextBytes(iv);
            Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
            cipher.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(key, "AES"),
                    new GCMParameterSpec(TAG_LENGTH_BITS, iv));
            byte[] ct = cipher.doFinal(plaintext == null ? new byte[0] : plaintext);
            byte[] out = new byte[HEADER_LENGTH + ct.length];
            out[0] = MAGIC[0];
            out[1] = MAGIC[1];
            out[2] = FORMAT_VERSION;
            System.arraycopy(iv, 0, out, 3, IV_LENGTH);
            System.arraycopy(ct, 0, out, HEADER_LENGTH, ct.length);
            return out;
        } catch (RootKeyException e) {
            throw e;
        } catch (Exception e) {
            throw new RootKeyException("加密失败", e);
        }
    }

    /** 解密并校验认证标签 */
    public byte[] decrypt(byte[] key, byte[] data) {
        if (key == null || key.length != 32) {
            throw new RootKeyException("AES-256 需要 32 字节根密钥，实际 " + (key == null ? 0 : key.length));
        }
        if (data == null || data.length < HEADER_LENGTH + TAG_LENGTH_BYTES) {
            throw new RootKeyException("密文长度非法（不足最小长度）");
        }
        if (data[0] != MAGIC[0] || data[1] != MAGIC[1]) {
            throw new RootKeyException("密文头非法（不是 rootkey 密文格式）");
        }
        if (data[2] != FORMAT_VERSION) {
            throw new RootKeyException("不支持的密文格式版本: " + data[2]);
        }
        try {
            byte[] iv = new byte[IV_LENGTH];
            System.arraycopy(data, 3, iv, 0, IV_LENGTH);
            Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
            cipher.init(Cipher.DECRYPT_MODE, new SecretKeySpec(key, "AES"),
                    new GCMParameterSpec(TAG_LENGTH_BITS, iv));
            byte[] ct = new byte[data.length - HEADER_LENGTH];
            System.arraycopy(data, HEADER_LENGTH, ct, 0, ct.length);
            return cipher.doFinal(ct);
        } catch (javax.crypto.AEADBadTagException e) {
            throw new RootKeyException("解密失败：密文被篡改或密钥不匹配", e);
        } catch (RootKeyException e) {
            throw e;
        } catch (Exception e) {
            throw new RootKeyException("解密失败", e);
        }
    }
}
