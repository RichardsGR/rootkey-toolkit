package com.metrace.rootkey.core;

import com.metrace.rootkey.RootKeyConstants;
import com.metrace.rootkey.RootKeyException;
import com.metrace.rootkey.internal.Codec;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.attribute.PosixFilePermissions;
import java.security.SecureRandom;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;
import java.util.Properties;

/**
 * 根密钥与四组件的生成器（4-of-4 XOR 分片）。
 *
 * <p>派生方式（全部为 32 字节随机材料）：</p>
 * <ul>
 *   <li>root = SecureRandom 随机产生（AES-256 根密钥）</li>
 *   <li>a、b、c = SecureRandom 各自独立随机</li>
 *   <li>d = root XOR a XOR b XOR c</li>
 * </ul>
 * <p>还原时 a XOR b XOR c XOR d == root，字节级确定，顺序无关。</p>
 */
public final class RootKeyGenerator {

    /** 生成结果：文件位置 + keyId/KCV + 内存中的根密钥（调用方负责 close 销毁） */
    public static final class GenerateResult implements AutoCloseable {
        private final String keyId;
        private final String kcvHex;
        private final List<Path> componentPaths;
        private final Path manifestPath;
        private final RootKeySecret secret;

        private GenerateResult(String keyId, String kcvHex, List<Path> componentPaths,
                               Path manifestPath, RootKeySecret secret) {
            this.keyId = keyId;
            this.kcvHex = kcvHex;
            this.componentPaths = componentPaths;
            this.manifestPath = manifestPath;
            this.secret = secret;
        }

        public String keyId() {
            return keyId;
        }

        public String kcvHex() {
            return kcvHex;
        }

        /** 按 a/b/c/d 顺序返回四个组件文件路径 */
        public List<Path> componentPaths() {
            return new ArrayList<Path>(componentPaths);
        }

        public Path manifestPath() {
            return manifestPath;
        }

        /** 生成的根密钥（仅内存中，文件不落盘；用完必须 close） */
        public RootKeySecret secret() {
            return secret;
        }

        @Override
        public void close() {
            secret.destroy();
        }
    }

    private RootKeyGenerator() {
    }

    /**
     * 生成根密钥与四个组件文件。
     *
     * @param outDir 输出目录（自动创建）
     * @param keyId  密钥标识（1-64 位字母/数字/./_/-）
     * @param force  目标文件已存在时是否覆盖
     */
    public static GenerateResult generate(Path outDir, String keyId, boolean force) {
        return generate(outDir, keyId, force, new SecureRandom());
    }

    public static GenerateResult generate(Path outDir, String keyId, boolean force, SecureRandom random) {
        try {
            Files.createDirectories(outDir);
        } catch (IOException e) {
            throw new RootKeyException("无法创建输出目录: " + outDir, e);
        }

        List<Path> paths = new ArrayList<Path>();
        for (char label : RootKeyConstants.COMPONENT_LABELS) {
            paths.add(outDir.resolve(label + RootKeyConstants.COMPONENT_FILE_SUFFIX));
        }
        Path manifestPath = outDir.resolve("manifest.properties");

        if (!force) {
            List<String> existing = new ArrayList<String>();
            for (Path p : paths) {
                if (Files.exists(p)) {
                    existing.add(p.toString());
                }
            }
            if (Files.exists(manifestPath)) {
                existing.add(manifestPath.toString());
            }
            if (!existing.isEmpty()) {
                throw new RootKeyException("目标文件已存在（如需覆盖请加 --force）: "
                        + String.join(", ", existing));
            }
        }

        // —— 派生：root、a、b、c 随机；d = root ⊕ a ⊕ b ⊕ c ——
        byte[] root = new byte[RootKeyConstants.ROOT_KEY_LENGTH_BYTES];
        random.nextBytes(root);
        byte[][] mats = new byte[4][];
        for (int i = 0; i < 3; i++) {
            mats[i] = new byte[RootKeyConstants.ROOT_KEY_LENGTH_BYTES];
            random.nextBytes(mats[i]);
        }
        mats[3] = Codec.xorAll(root, mats[0], mats[1], mats[2]);

        String kcv = RootKeySecret.computeKcv(root);
        for (int i = 0; i < 4; i++) {
            char label = RootKeyConstants.COMPONENT_LABELS[i];
            ComponentFile.create(keyId, label, mats[i], kcv).save(paths.get(i));
        }
        writeManifest(manifestPath, keyId, kcv);

        // RootKeySecret 构造时内部克隆密钥；随后本地临时材料即刻清零，
        // 根密钥仅存在于返回的 secret 中，由调用方负责 close 销毁
        RootKeySecret secret = new RootKeySecret(keyId, kcv, root);
        java.util.Arrays.fill(root, (byte) 0);
        for (byte[] m : mats) {
            java.util.Arrays.fill(m, (byte) 0);
        }
        return new GenerateResult(keyId, kcv, paths, manifestPath, secret);
    }

    private static void writeManifest(Path path, String keyId, String kcv) {
        Properties props = new Properties();
        props.setProperty("keyId", keyId);
        props.setProperty("algorithm", "AES-256");
        props.setProperty("shareScheme", "XOR-4-of-4");
        props.setProperty("kcv", kcv);
        props.setProperty("createdAt", new SimpleDateFormat("yyyy-MM-dd'T'HH:mm:ssXXX").format(new Date()));
        props.setProperty("toolVersion", RootKeyConstants.TOOL_VERSION);
        try {
            Files.write(path, manifestBytes(props),
                    java.nio.file.StandardOpenOption.CREATE,
                    java.nio.file.StandardOpenOption.TRUNCATE_EXISTING,
                    java.nio.file.StandardOpenOption.WRITE);
        } catch (IOException e) {
            throw new RootKeyException("无法写入 manifest 文件: " + path, e);
        }
        try {
            Files.setPosixFilePermissions(path, PosixFilePermissions.fromString("rw-------"));
        } catch (Exception ignore) {
            // 非 POSIX 文件系统跳过
        }
    }

    private static byte[] manifestBytes(Properties props) {
        StringBuilder sb = new StringBuilder();
        sb.append("# RootKey manifest（信息文件，不参与还原；还原仅需 4 个 .comp 组件文件）\n");
        for (String k : new String[]{"keyId", "algorithm", "shareScheme", "kcv", "createdAt", "toolVersion"}) {
            sb.append(k).append('=').append(props.getProperty(k)).append('\n');
        }
        return sb.toString().getBytes(StandardCharsets.UTF_8);
    }

    /** 默认 keyId：rk-yyyyMMddHHmmss */
    public static String defaultKeyId() {
        return "rk-" + new SimpleDateFormat("yyyyMMddHHmmss").format(new Date());
    }
}
