package com.metrace.rootkey.core;

import com.metrace.rootkey.RootKeyConstants;
import com.metrace.rootkey.RootKeyException;
import com.metrace.rootkey.internal.Codec;

import javax.crypto.spec.SecretKeySpec;
import java.util.Arrays;

/**
 * 内存中的根密钥载体：持有 32 字节 AES-256 密钥与其 KCV 指纹。
 *
 * <p>遵循 {@link AutoCloseable}：用完调用 {@link #close()} 即刻将密钥字节清零，
 * 缩短敏感数据在内存中的存活时间。KCV（SHA-256 前 8 字节）用于比对/日志，
 * 不泄露密钥信息。</p>
 */
public final class RootKeySecret implements AutoCloseable {

    private final String keyId;
    private final String kcvHex;
    private byte[] key;
    private boolean destroyed;

    RootKeySecret(String keyId, String kcvHex, byte[] key) {
        if (key == null || key.length != RootKeyConstants.ROOT_KEY_LENGTH_BYTES) {
            throw new RootKeyException("根密钥长度必须为 32 字节");
        }
        this.keyId = keyId;
        this.kcvHex = kcvHex.toLowerCase();
        this.key = key.clone();
    }

    /** 计算根密钥的 KCV（SHA-256 前 8 字节的十六进制） */
    public static String computeKcv(byte[] key) {
        byte[] digest = Codec.sha256(key);
        byte[] kcv = Arrays.copyOf(digest, RootKeyConstants.KCV_LENGTH_BYTES);
        return Codec.toHex(kcv);
    }

    public String keyId() {
        return keyId;
    }

    public String kcvHex() {
        return kcvHex;
    }

    public boolean isDestroyed() {
        return destroyed;
    }

    /**
     * 转为 JCE 的 AES SecretKey（JCE 内部会持有自己的副本）。
     */
    public synchronized SecretKeySpec toSecretKey() {
        requireAlive();
        return new SecretKeySpec(key, "AES");
    }

    /**
     * 导出原始密钥字节（副本）。请谨慎使用，仅用于需要裸字节的场景。
     */
    public synchronized byte[] exportKey() {
        requireAlive();
        return key.clone();
    }

    /**
     * 立即销毁内存中的密钥字节。
     */
    public synchronized void destroy() {
        if (!destroyed) {
            Arrays.fill(key, (byte) 0);
            destroyed = true;
        }
    }

    @Override
    public void close() {
        destroy();
    }

    private void requireAlive() {
        if (destroyed) {
            throw new RootKeyException("根密钥已销毁，无法继续使用（请重新还原）");
        }
    }
}
