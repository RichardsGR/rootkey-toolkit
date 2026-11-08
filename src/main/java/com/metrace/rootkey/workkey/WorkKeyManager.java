package com.metrace.rootkey.workkey;

import com.metrace.rootkey.RootKeyConstants;
import com.metrace.rootkey.RootKeyException;
import com.metrace.rootkey.RootKeyManager;
import com.metrace.rootkey.core.RootKeySecret;
import com.metrace.rootkey.crypto.AesGcmCipher;
import com.metrace.rootkey.internal.Codec;

import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.SecureRandom;
import java.util.Base64;

/**
 * 工作密钥（WorkKey）管理器：信封加密模式。
 *
 * <p>职责分工：</p>
 * <ul>
 *   <li><b>RootKey（根密钥）</b>：四组件分片保管，只用来加密/还原 WorkKey，
 *       从不直接加密业务数据</li>
 *   <li><b>WorkKey（工作密钥）</b>：32 字节随机 AES-256 密钥，负责加密业务数据；
 *       生成后立即用 RootKey 加密落盘（.workkey 文件），可安全分发到业务侧</li>
 * </ul>
 *
 * <p>生成（管理侧）：</p>
 * <pre>
 *   try (RootKeyManager root = RootKeyManager.fromConfigFile(cfg);
 *        WorkKeyManager.Generated g = WorkKeyManager.generate(
 *                Paths.get("mydb-key.workkey"), "mydb-key", root, false)) {
 *       g.secret();  // 内存中可直接使用的工作密钥
 *   }
 * </pre>
 *
 * <p>业务侧使用（根据根密钥配置 + WorkKey 文件路径还原到内存）：</p>
 * <pre>
 *   try (RootKeyManager root = RootKeyManager.fromConfigFile(cfg);
 *        WorkKeyManager wk = new WorkKeyManager(root, Paths.get("mydb-key.workkey"))) {
 *       String ct = wk.encryptToBase64("业务数据");
 *       String pt = wk.decryptFromBase64(ct);
 *   }
 * </pre>
 */
public final class WorkKeyManager implements AutoCloseable {

    private final RootKeyManager root;
    private final AesGcmCipher cipher;
    private final Path workKeyFile;
    private WorkKeySecret cached;

    private WorkKeyManager(RootKeyManager root, Path workKeyFile, AesGcmCipher cipher) {
        if (root == null) {
            throw new RootKeyException("root（根密钥管理器）不能为空");
        }
        this.root = root;
        this.cipher = cipher;
        this.workKeyFile = workKeyFile;
    }

    /**
     * 业务侧构造：绑定根密钥与工作密钥文件。
     * 首次加解密时惰性还原 WorkKey 到内存并缓存；close() 销毁。
     */
    public WorkKeyManager(RootKeyManager root, Path workKeyFile) {
        this(root, workKeyFile, new AesGcmCipher());
    }

    // ------------------------------------------------------------------ 生成（管理侧）

    /** 生成结果：文件位置 + 内存中的工作密钥（调用方负责 close） */
    public static final class Generated implements AutoCloseable {
        private final WorkKeySecret secret;
        private final Path file;

        private Generated(WorkKeySecret secret, Path file) {
            this.secret = secret;
            this.file = file;
        }

        public WorkKeySecret secret() {
            return secret;
        }

        public Path file() {
            return file;
        }

        public String name() {
            return secret.name();
        }

        public String kcvHex() {
            return secret.kcvHex();
        }

        @Override
        public void close() {
            secret.destroy();
        }
    }

    /**
     * 生成工作密钥：随机 32 字节 → 用根密钥（AES-256-GCM）加密 → 落盘为 .workkey 文件。
     *
     * @param outFile 输出文件（为 null 时用 &lt;name&gt;.workkey）
     * @param name    工作密钥名称（用户指定，1-64 位字母/数字/./_/-）
     * @param root    已配置组件位置的根密钥管理器
     * @param force   文件已存在时是否覆盖
     */
    public static Generated generate(Path outFile, String name, RootKeyManager root, boolean force) {
        return generate(outFile, name, root, force, new SecureRandom());
    }

    public static Generated generate(Path outFile, String name, RootKeyManager root,
                                     boolean force, SecureRandom random) {
        if (name == null || !RootKeyConstants.NAME_PATTERN.matcher(name).matches()) {
            throw new RootKeyException("非法工作密钥名称: '" + name + "'（仅允许 1-64 位字母/数字/./_/-）");
        }
        Path file = outFile != null ? outFile : Paths.get(name + RootKeyConstants.WORKKEY_FILE_SUFFIX);
        if (!force && Files.exists(file)) {
            throw new RootKeyException("目标文件已存在（如需覆盖请加 --force）: " + file);
        }
        // 生成 32 字节随机工作密钥，立即用根密钥加密（信封）
        byte[] wk = new byte[RootKeyConstants.ROOT_KEY_LENGTH_BYTES];
        random.nextBytes(wk);
        byte[] wrapped;
        try {
            wrapped = new AesGcmCipher().encrypt(root.secret().exportKey(), wk);
        } finally {
            // wrapped 已生成，临时密钥材料不再需要明文形态时交给 WorkKeySecret 接管副本
        }
        WorkKeyFile f = WorkKeyFile.create(name, root.keyId(), root.kcv(),
                RootKeySecret.computeKcv(wk), wrapped);
        f.save(file);
        WorkKeySecret secret = WorkKeySecret.create(name, wk);
        java.util.Arrays.fill(wk, (byte) 0);
        return new Generated(secret, file.toAbsolutePath().normalize());
    }

    // ------------------------------------------------------------------ 还原（业务侧）

    /** 惰性还原并缓存（线程安全）；每次调用返回同一实例 */
    public synchronized WorkKeySecret secret() {
        if (cached == null) {
            cached = restore(workKeyFile, root);
        }
        return cached;
    }

    public String name() {
        return secret().name();
    }

    public String kcv() {
        return secret().kcvHex();
    }

    /**
     * 一次性还原：根据 WorkKey 文件 + 根密钥，把 WorkKey 还原到内存。
     * 依次校验：文件 checksum → 根密钥归属（rootKeyId/rootKcv）→ GCM 认证 → WorkKey KCV 自证。
     */
    public static WorkKeySecret restore(Path workKeyFile, RootKeyManager root) {
        if (workKeyFile == null) {
            throw new RootKeyException("缺少工作密钥文件路径");
        }
        WorkKeyFile f = WorkKeyFile.load(workKeyFile);
        // 根密钥归属核对：避免拿错根密钥时给出晦涩的 GCM 报错
        if (!f.rootKcvHex().equalsIgnoreCase(root.kcv()) || !f.rootKeyId().equals(root.keyId())) {
            throw new RootKeyException("根密钥不匹配：工作密钥 '" + f.name() + "' 是由 rootKeyId="
                    + f.rootKeyId() + " (KCV=" + f.rootKcvHex() + ") 加密的，"
                    + "当前根密钥为 rootKeyId=" + root.keyId() + " (KCV=" + root.kcv() + ")");
        }
        byte[] key = new AesGcmCipher().decrypt(root.secret().exportKey(), f.wrapped());
        WorkKeySecret secret = WorkKeySecret.create(f.name(), key);
        java.util.Arrays.fill(key, (byte) 0);
        if (!secret.kcvHex().equalsIgnoreCase(f.kcvHex())) {
            secret.destroy();
            throw new RootKeyException("工作密钥 KCV 校验失败: 还原结果 " + secret.kcvHex()
                    + " 与文件记录 " + f.kcvHex() + " 不一致");
        }
        return secret;
    }

    // ------------------------------------------------------------------ 业务加解密（AES-256-GCM）

    /** 用工作密钥加密（二进制） */
    public byte[] encrypt(byte[] plaintext) {
        return cipher.encrypt(secret().exportKey(), plaintext);
    }

    /** 用工作密钥解密（二进制） */
    public byte[] decrypt(byte[] ciphertext) {
        return cipher.decrypt(secret().exportKey(), ciphertext);
    }

    /** 用工作密钥加密（UTF-8 文本 → Base64 密文） */
    public String encryptToBase64(String plaintext) {
        byte[] ct = encrypt(plaintext.getBytes(StandardCharsets.UTF_8));
        return Base64.getEncoder().encodeToString(ct);
    }

    /** 用工作密钥解密（Base64 密文 → UTF-8 文本） */
    public String decryptFromBase64(String ciphertextB64) {
        byte[] data;
        try {
            data = Base64.getDecoder().decode(ciphertextB64 == null ? "" : ciphertextB64.trim());
        } catch (IllegalArgumentException e) {
            throw new RootKeyException("输入不是合法的 Base64 密文");
        }
        return new String(decrypt(data), StandardCharsets.UTF_8);
    }

    /** 销毁内存中的工作密钥；之后再次使用会自动重新还原 */
    @Override
    public synchronized void close() {
        if (cached != null) {
            cached.destroy();
            cached = null;
        }
    }
}
