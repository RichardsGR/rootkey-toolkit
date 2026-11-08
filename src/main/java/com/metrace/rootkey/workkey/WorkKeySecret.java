package com.metrace.rootkey.workkey;

import com.metrace.rootkey.RootKeyConstants;
import com.metrace.rootkey.RootKeyException;
import com.metrace.rootkey.core.RootKeySecret;

import javax.crypto.spec.SecretKeySpec;
import java.util.Arrays;

/**
 * 内存中的工作密钥载体：32 字节 AES-256 密钥 + 名称 + KCV 指纹。
 *
 * <p>与 {@link RootKeySecret} 同样的纪律：AutoCloseable，用完 {@link #destroy()}
 * 即刻清零内存；KCV 可用于日志/比对，不泄露密钥。</p>
 */
public final class WorkKeySecret implements AutoCloseable {

    private final String name;
    private final String kcvHex;
    private byte[] key;
    private boolean destroyed;

    private WorkKeySecret(String name, String kcvHex, byte[] key) {
        this.name = name;
        this.kcvHex = kcvHex.toLowerCase();
        this.key = key;
    }

    /**
     * 创建工作密钥对象并校验名称/KCV；KCV 由密钥现场计算。
     */
    public static WorkKeySecret create(String name, byte[] key) {
        if (name == null || !RootKeyConstants.NAME_PATTERN.matcher(name).matches()) {
            throw new RootKeyException("非法工作密钥名称: '" + name + "'（仅允许 1-64 位字母/数字/./_/-）");
        }
        if (key == null || key.length != RootKeyConstants.ROOT_KEY_LENGTH_BYTES) {
            throw new RootKeyException("工作密钥长度必须为 32 字节（AES-256）");
        }
        return new WorkKeySecret(name, RootKeySecret.computeKcv(key), key.clone());
    }

    public String name() {
        return name;
    }

    /** 工作密钥 KCV（SHA-256 前 8 字节），可用于日志/比对 */
    public String kcvHex() {
        return kcvHex;
    }

    public boolean isDestroyed() {
        return destroyed;
    }

    /** 转为 JCE 的 AES SecretKey（JCE 内部持有自己的副本） */
    public synchronized SecretKeySpec toSecretKey() {
        requireAlive();
        return new SecretKeySpec(key, "AES");
    }

    /** 导出原始密钥字节（副本）。谨慎使用。 */
    public synchronized byte[] exportKey() {
        requireAlive();
        return key.clone();
    }

    /** 立即销毁内存中的密钥字节 */
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
            throw new RootKeyException("工作密钥 '" + name + "' 已销毁，无法继续使用（请重新还原）");
        }
    }
}
