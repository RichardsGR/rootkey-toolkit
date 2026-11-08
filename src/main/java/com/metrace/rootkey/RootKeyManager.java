package com.metrace.rootkey;

import com.metrace.rootkey.config.RootKeyConfig;
import com.metrace.rootkey.core.RootKeyGenerator;
import com.metrace.rootkey.core.RootKeyRestorer;
import com.metrace.rootkey.core.RootKeySecret;
import com.metrace.rootkey.crypto.AesGcmCipher;

import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.util.Base64;
import java.util.Properties;

/**
 * 根密钥管理门面（SDK 主入口）。
 *
 * <p>服务器端典型用法：</p>
 * <pre>
 *   RootKeyConfig config = RootKeyConfig.load(Paths.get("/etc/app/rootkey.properties"));
 *   try (RootKeyManager km = new RootKeyManager(config)) {
 *       String cipherB64 = km.encryptToBase64("机密数据");
 *       String plain     = km.decryptFromBase64(cipherB64);
 *   }
 * </pre>
 *
 * <p>首次调用加解密时按配置位置加载四组件并还原根密钥（惰性、缓存、线程安全）；
 * close() 时销毁内存中的根密钥。</p>
 */
public final class RootKeyManager implements AutoCloseable {

    private final RootKeyConfig config;
    private final AesGcmCipher cipher;
    private RootKeySecret secret;

    public RootKeyManager(RootKeyConfig config) {
        this(config, new AesGcmCipher());
    }

    public RootKeyManager(RootKeyConfig config, AesGcmCipher cipher) {
        if (config == null || cipher == null) {
            throw new RootKeyException("config 与 cipher 均不能为空");
        }
        this.config = config;
        this.cipher = cipher;
    }

    public static RootKeyManager fromConfigFile(Path configFile) {
        return new RootKeyManager(RootKeyConfig.load(configFile));
    }

    public static RootKeyManager fromProperties(Properties properties) {
        return new RootKeyManager(RootKeyConfig.fromProperties(properties));
    }

    /**
     * 生成根密钥四组件（本地管理工具使用）。根密钥本身不落盘。
     */
    public static RootKeyGenerator.GenerateResult generate(Path outDir, String keyId, boolean force) {
        return RootKeyGenerator.generate(outDir, keyId, force);
    }

    /** 还原（惰性、缓存、线程安全） */
    public synchronized RootKeySecret secret() {
        if (secret == null) {
            secret = RootKeyRestorer.restore(config.aPath(), config.bPath(), config.cPath(), config.dPath());
        }
        return secret;
    }

    /** keyId（还原后可用；未还原时触发一次还原） */
    public String keyId() {
        return secret().keyId();
    }

    /** 根密钥 KCV（可用于与生成端核对，不泄露密钥） */
    public String kcv() {
        return secret().kcvHex();
    }

    /** 加密（二进制） */
    public byte[] encrypt(byte[] plaintext) {
        return cipher.encrypt(secret().toSecretKey().getEncoded(), plaintext);
    }

    /** 解密（二进制） */
    public byte[] decrypt(byte[] ciphertext) {
        return cipher.decrypt(secret().toSecretKey().getEncoded(), ciphertext);
    }

    /** 加密（UTF-8 文本 → Base64 密文，适合入库/传输） */
    public String encryptToBase64(String plaintext) {
        byte[] ct = encrypt(plaintext.getBytes(StandardCharsets.UTF_8));
        return Base64.getEncoder().encodeToString(ct);
    }

    /** 解密（Base64 密文 → UTF-8 文本） */
    public String decryptFromBase64(String ciphertextB64) {
        byte[] data;
        try {
            data = Base64.getDecoder().decode(ciphertextB64 == null ? "" : ciphertextB64.trim());
        } catch (IllegalArgumentException e) {
            throw new RootKeyException("输入不是合法的 Base64 密文");
        }
        return new String(decrypt(data), StandardCharsets.UTF_8);
    }

    /** 立即销毁内存中的根密钥；之后再次使用会自动重新还原 */
    @Override
    public synchronized void close() {
        if (secret != null) {
            secret.destroy();
            secret = null;
        }
    }
}
