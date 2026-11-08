package com.metrace.rootkey.workkey;

import com.metrace.rootkey.RootKeyConstants;
import com.metrace.rootkey.RootKeyException;
import com.metrace.rootkey.RootKeyManager;
import com.metrace.rootkey.core.RootKeySecret;
import com.metrace.rootkey.crypto.AesGcmCipher;

import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;

/**
 * 工作密钥（WorkKey）管理器：信封加密模式。
 *
 * <p>职责分工：</p>
 * <ul>
 *   <li><b>RootKey（根密钥）</b>：四组件分片保管，只用来加密/还原 WorkKey，
 *       从不直接加密业务数据</li>
 *   <li><b>WorkKey（工作密钥）</b>：32 字节随机 AES-256 密钥，负责加密业务数据；
 *       生成后立即用 RootKey 加密，写入 JSON 工作密钥文件</li>
 * </ul>
 *
 * <p>一个 .json 工作密钥文件可存放<b>多个</b>工作密钥（按名称区分）：
 * 对已存在的文件再次 generate 会追加新条目；同名条目需 force 才覆盖。</p>
 *
 * <p>业务侧使用（根据根密钥配置 + 工作密钥文件路径 + 名称还原到内存）：</p>
 * <pre>
 *   try (RootKeyManager root = RootKeyManager.fromConfigFile(cfg);
 *        WorkKeyManager wk = new WorkKeyManager(root,
 *                Paths.get("keys.json"), "order-db")) {
 *       String ct = wk.encryptToBase64("业务数据");
 *       String pt = wk.decryptFromBase64(ct);
 *   }
 * </pre>
 * <p>文件只有一个密钥时名称可传 null。</p>
 */
public final class WorkKeyManager implements AutoCloseable {

    private final RootKeyManager root;
    private final AesGcmCipher cipher;
    private final Path workKeyFile;
    private final String keyName;
    private WorkKeySecret cached;

    /**
     * 业务侧构造：绑定根密钥、工作密钥文件与密钥名称。
     * 文件内只有一个密钥时 name 可为 null；首次加解密时惰性还原并缓存，close() 销毁。
     */
    public WorkKeyManager(RootKeyManager root, Path workKeyFile, String keyName) {
        if (root == null) {
            throw new RootKeyException("root（根密钥管理器）不能为空");
        }
        this.root = root;
        this.cipher = new AesGcmCipher();
        this.workKeyFile = workKeyFile;
        this.keyName = normalizeName(keyName);
    }

    private static String normalizeName(String name) {
        return name == null || name.trim().isEmpty() ? null : name.trim();
    }

    // ------------------------------------------------------------------ 生成（管理侧）

    /** 生成结果：文件位置 + 文件内现有密钥名 + 内存中的本次工作密钥（调用方负责 close） */
    public static final class Generated implements AutoCloseable {
        private final WorkKeySecret secret;
        private final Path file;
        private final List<String> namesInFile;

        private Generated(WorkKeySecret secret, Path file, List<String> namesInFile) {
            this.secret = secret;
            this.file = file;
            this.namesInFile = namesInFile;
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

        /** 生成后文件内全部密钥名称（按存放顺序） */
        public List<String> namesInFile() {
            return new ArrayList<String>(namesInFile);
        }

        @Override
        public void close() {
            secret.destroy();
        }
    }

    /**
     * 生成工作密钥：随机 32 字节 → 用根密钥（AES-256-GCM）加密 → 写入 JSON 工作密钥文件。
     *
     * <p>文件已存在时为<b>追加</b>（校验根密钥归属一致）；同名条目需 {@code force} 覆盖。</p>
     *
     * @param outFile 输出文件（为 null 时用 &lt;name&gt;.json）
     * @param name    工作密钥名称（用户指定，1-64 位字母/数字/./_/-）
     * @param root    已配置组件位置的根密钥管理器
     * @param force   同名条目已存在时是否覆盖
     */
    public static Generated generate(Path outFile, String name, RootKeyManager root, boolean force) {
        return generate(outFile, name, root, force, new SecureRandom());
    }

    public static Generated generate(Path outFile, String name, RootKeyManager root,
                                     boolean force, SecureRandom random) {
        String keyName = normalizeName(name);
        if (keyName == null || !RootKeyConstants.NAME_PATTERN.matcher(keyName).matches()) {
            throw new RootKeyException("非法工作密钥名称: '" + name + "'（仅允许 1-64 位字母/数字/./_/-）");
        }
        Path file = outFile != null ? outFile : Paths.get(keyName + RootKeyConstants.WORKKEY_FILE_SUFFIX);

        WorkKeyFile f;
        if (Files.exists(file)) {
            f = WorkKeyFile.load(file);
            // 追加必须同根密钥：防止把不同根密钥的密钥混进同一文件
            if (!f.rootKcvHex().equalsIgnoreCase(root.kcv()) || !f.rootKeyId().equals(root.keyId())) {
                throw new RootKeyException("目标文件已由 rootKeyId=" + f.rootKeyId()
                        + " (KCV=" + f.rootKcvHex() + ") 的根密钥加密，与当前根密钥（rootKeyId="
                        + root.keyId() + "）不一致，请换一个文件: " + file);
            }
            if (f.hasEntry(keyName) && !force) {
                throw new RootKeyException("文件中已存在同名工作密钥 '" + keyName
                        + "'（覆盖请加 --force）: " + file);
            }
        } else {
            f = WorkKeyFile.create(root.keyId(), root.kcv());
        }

        // 生成 32 字节随机工作密钥，立即用根密钥加密（信封）
        byte[] wk = new byte[RootKeyConstants.ROOT_KEY_LENGTH_BYTES];
        random.nextBytes(wk);
        byte[] wrapped = new AesGcmCipher().encrypt(root.secret().exportKey(), wk);
        f.put(WorkKeyFile.entry(keyName, root.keyId(), root.kcv(),
                RootKeySecret.computeKcv(wk), wrapped));
        f.save(file);

        WorkKeySecret secret = WorkKeySecret.create(keyName, wk);
        java.util.Arrays.fill(wk, (byte) 0);
        return new Generated(secret, file.toAbsolutePath().normalize(), f.names());
    }

    // ------------------------------------------------------------------ 还原（业务侧）

    /** 惰性还原并缓存（线程安全）；每次调用返回同一实例 */
    public synchronized WorkKeySecret secret() {
        if (cached == null) {
            cached = restore(workKeyFile, keyName, root);
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
     * 一次性还原：根据工作密钥文件 + 名称 + 根密钥，把 WorkKey 还原到内存。
     *
     * <p>{@code name} 为 null 时文件必须恰好只有一个密钥。依次校验：
     * 文件 JSON/checksum → 根密钥归属（rootKeyId/rootKcv）→ GCM 认证 → WorkKey KCV 自证。</p>
     */
    public static WorkKeySecret restore(Path workKeyFile, String name, RootKeyManager root) {
        if (workKeyFile == null) {
            throw new RootKeyException("缺少工作密钥文件路径");
        }
        WorkKeyFile f = WorkKeyFile.load(workKeyFile);
        // 根密钥归属核对：避免拿错根密钥时给出晦涩的 GCM 报错
        if (!f.rootKcvHex().equalsIgnoreCase(root.kcv()) || !f.rootKeyId().equals(root.keyId())) {
            throw new RootKeyException("根密钥不匹配：工作密钥文件由 rootKeyId=" + f.rootKeyId()
                    + " (KCV=" + f.rootKcvHex() + ") 加密，当前根密钥为 rootKeyId="
                    + root.keyId() + " (KCV=" + root.kcv() + ")");
        }
        String keyName = normalizeName(name);
        if (keyName == null) {
            if (f.keyCount() != 1) {
                throw new RootKeyException("文件内含 " + f.keyCount()
                        + " 个工作密钥（" + f.names() + "），请通过 name 参数指定要还原哪一个");
            }
            keyName = f.names().get(0);
        }
        WorkKeyFile.Entry e = f.getEntry(keyName);
        byte[] key = new AesGcmCipher().decrypt(root.secret().exportKey(), e.wrapped());
        WorkKeySecret secret = WorkKeySecret.create(e.name(), key);
        java.util.Arrays.fill(key, (byte) 0);
        if (!secret.kcvHex().equalsIgnoreCase(e.kcvHex())) {
            secret.destroy();
            throw new RootKeyException("工作密钥 '" + e.name() + "' KCV 校验失败: 还原结果 " + secret.kcvHex()
                    + " 与文件记录 " + e.kcvHex() + " 不一致");
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
