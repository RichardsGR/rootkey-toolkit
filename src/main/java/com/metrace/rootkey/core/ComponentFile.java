package com.metrace.rootkey.core;

import com.metrace.rootkey.RootKeyConstants;
import com.metrace.rootkey.RootKeyException;
import com.metrace.rootkey.internal.Codec;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.attribute.PosixFilePermissions;
import java.util.Base64;
import java.util.regex.Pattern;

/**
 * 组件文件：根密钥四份材料（a/b/c/d）之一的落盘载体。
 *
 * <p>文件为 UTF-8 文本，行式 key=value，自带 SHA-256 校验和，
 * 任何对内容的意外改动都可在加载时被发现。文件格式：</p>
 *
 * <pre>
 *   # 注释行
 *   version=1
 *   keyId=order-service-2026
 *   component=a
 *   algorithm=AES
 *   material=&lt;Base64(32字节)&gt;
 *   kcv=&lt;16位十六进制，根密钥指纹&gt;
 *   checksum=&lt;64位十六进制，覆盖上述全部字段&gt;
 * </pre>
 */
public final class ComponentFile {

    /** keyId 仅允许安全字符，保证 canonical 串无歧义（规则统一收敛在常量类） */
    static final Pattern KEY_ID_PATTERN = RootKeyConstants.NAME_PATTERN;

    private static final Pattern HEX_16 = Pattern.compile("^[0-9a-fA-F]{16}$");
    private static final Pattern HEX_64 = Pattern.compile("^[0-9a-fA-F]{64}$");

    private final int version;
    private final String keyId;
    private final char label;
    private final String algorithm;
    private final byte[] material;
    private final String kcvHex;

    private ComponentFile(int version, String keyId, char label, String algorithm,
                          byte[] material, String kcvHex) {
        this.version = version;
        this.keyId = keyId;
        this.label = label;
        this.algorithm = algorithm;
        this.material = material.clone();
        this.kcvHex = kcvHex.toLowerCase();
    }

    /**
     * 创建组件对象（内存态，不落盘）。
     */
    public static ComponentFile create(String keyId, char label, byte[] material, String kcvHex) {
        if (keyId == null || !KEY_ID_PATTERN.matcher(keyId).matches()) {
            throw new RootKeyException("非法 keyId: '" + keyId + "'（仅允许 1-64 位字母/数字/./_/-）");
        }
        if (!isLabel(label)) {
            throw new RootKeyException("非法组件标签: '" + label + "'（仅允许 a/b/c/d）");
        }
        if (material == null || material.length != RootKeyConstants.ROOT_KEY_LENGTH_BYTES) {
            throw new RootKeyException("组件材料长度必须为 " + RootKeyConstants.ROOT_KEY_LENGTH_BYTES + " 字节");
        }
        if (kcvHex == null || !HEX_16.matcher(kcvHex).matches()) {
            throw new RootKeyException("非法 KCV: '" + kcvHex + "'（应为 16 位十六进制）");
        }
        return new ComponentFile(RootKeyConstants.FILE_FORMAT_VERSION, keyId, label,
                RootKeyConstants.ALGORITHM, material, kcvHex);
    }

    public static boolean isLabel(char c) {
        for (char allowed : RootKeyConstants.COMPONENT_LABELS) {
            if (allowed == c) {
                return true;
            }
        }
        return false;
    }

    /**
     * 从文件加载并完整校验（格式、长度、checksum）。
     */
    public static ComponentFile load(Path path) {
        java.util.List<String> lines;
        try {
            lines = Files.readAllLines(path, StandardCharsets.UTF_8);
        } catch (IOException e) {
            throw new RootKeyException("无法读取组件文件: " + path, e);
        }
        java.util.Map<String, String> map = new java.util.LinkedHashMap<String, String>();
        for (String raw : lines) {
            String line = raw.trim();
            if (line.isEmpty() || line.startsWith("#")) {
                continue;
            }
            int eq = line.indexOf('=');
            if (eq <= 0) {
                throw new RootKeyException("组件文件格式错误（无法解析的行）: " + path + " -> \"" + line + "\"");
            }
            String k = line.substring(0, eq).trim();
            String v = line.substring(eq + 1).trim();
            if (map.put(k, v) != null) {
                throw new RootKeyException("组件文件存在重复字段 '" + k + "': " + path);
            }
        }
        for (String required : new String[]{"version", "keyId", "component", "algorithm", "material", "kcv", "checksum"}) {
            if (!map.containsKey(required)) {
                throw new RootKeyException("组件文件缺少字段 '" + required + "': " + path);
            }
        }

        int version;
        try {
            version = Integer.parseInt(map.get("version"));
        } catch (NumberFormatException e) {
            throw new RootKeyException("组件文件 version 非法: " + path);
        }
        if (version != RootKeyConstants.FILE_FORMAT_VERSION) {
            throw new RootKeyException("组件文件版本不支持 (" + version + "): " + path);
        }
        String keyId = map.get("keyId");
        if (!KEY_ID_PATTERN.matcher(keyId).matches()) {
            throw new RootKeyException("组件文件 keyId 非法: '" + keyId + "': " + path);
        }
        String comp = map.get("component");
        if (comp.length() != 1 || !isLabel(comp.charAt(0))) {
            throw new RootKeyException("组件标签非法: '" + comp + "'（仅允许 a/b/c/d）: " + path);
        }
        if (!RootKeyConstants.ALGORITHM.equals(map.get("algorithm"))) {
            throw new RootKeyException("组件 algorithm 非法: '" + map.get("algorithm") + "'（当前仅支持 AES）: " + path);
        }
        byte[] material;
        try {
            material = Base64.getDecoder().decode(map.get("material"));
        } catch (IllegalArgumentException e) {
            throw new RootKeyException("组件 material 不是合法 Base64: " + path);
        }
        if (material.length != RootKeyConstants.ROOT_KEY_LENGTH_BYTES) {
            throw new RootKeyException("组件材料长度必须为 32 字节，实际 " + material.length + ": " + path);
        }
        String kcv = map.get("kcv");
        if (!HEX_16.matcher(kcv).matches()) {
            throw new RootKeyException("组件 kcv 非法: '" + kcv + "': " + path);
        }
        String checksum = map.get("checksum");
        if (!HEX_64.matcher(checksum).matches()) {
            throw new RootKeyException("组件 checksum 非法: " + path);
        }

        ComponentFile cf = new ComponentFile(version, keyId, comp.charAt(0),
                RootKeyConstants.ALGORITHM, material, kcv);
        if (!cf.checksumHex().equalsIgnoreCase(checksum)) {
            throw new RootKeyException("组件文件校验和不匹配（文件可能被篡改或损坏）: " + path
                    + "，期望 " + cf.checksumHex() + "，实际 " + checksum.toLowerCase());
        }
        return cf;
    }

    /** 校验和覆盖的全部字段拼成的规范串 */
    String canonical() {
        return version + "|" + keyId + "|" + label + "|" + Codec.b64(material) + "|" + kcvHex;
    }

    /** 对 canonical 串的 SHA-256（十六进制） */
    public String checksumHex() {
        return Codec.sha256Hex(canonical());
    }

    /**
     * 序列化为文件文本。
     */
    public String serialize() {
        StringBuilder sb = new StringBuilder(400);
        sb.append("# RootKey 组件文件（含敏感材料，请妥善保管，禁止提交到代码仓库）\n");
        sb.append("# keyId=").append(keyId).append(" component=").append(label).append('\n');
        sb.append("version=").append(version).append('\n');
        sb.append("keyId=").append(keyId).append('\n');
        sb.append("component=").append(label).append('\n');
        sb.append("algorithm=").append(algorithm).append('\n');
        sb.append("material=").append(Codec.b64(material)).append('\n');
        sb.append("kcv=").append(kcvHex).append('\n');
        sb.append("checksum=").append(checksumHex()).append('\n');
        return sb.toString();
    }

    /**
     * 保存到文件（权限尽力设为 600）。
     */
    public void save(Path path) {
        try {
            Files.write(path, serialize().getBytes(StandardCharsets.UTF_8),
                    java.nio.file.StandardOpenOption.CREATE,
                    java.nio.file.StandardOpenOption.TRUNCATE_EXISTING,
                    java.nio.file.StandardOpenOption.WRITE);
        } catch (IOException e) {
            throw new RootKeyException("无法写入组件文件: " + path, e);
        }
        try {
            Files.setPosixFilePermissions(path, PosixFilePermissions.fromString("rw-------"));
        } catch (Exception ignore) {
            // 非 POSIX 文件系统（如 Windows）跳过，不影响功能
        }
    }

    public int version() {
        return version;
    }

    public String keyId() {
        return keyId;
    }

    public char label() {
        return label;
    }

    public String algorithm() {
        return algorithm;
    }

    /** 组件材料（返回副本，防止外部持有引用后误清零） */
    public byte[] material() {
        return material.clone();
    }

    public String kcvHex() {
        return kcvHex;
    }
}
