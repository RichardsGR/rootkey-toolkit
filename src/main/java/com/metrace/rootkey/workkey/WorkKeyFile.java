package com.metrace.rootkey.workkey;

import com.metrace.rootkey.RootKeyConstants;
import com.metrace.rootkey.RootKeyException;
import com.metrace.rootkey.internal.Codec;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.attribute.PosixFilePermissions;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * 工作密钥文件：被根密钥加密后的 WorkKey 落盘载体（信封加密的"信封"）。
 *
 * <p>文件本身可以存放在业务侧——其中只有被 AES-256-GCM 加密的密钥材料，
 * 没有根密钥的四个组件无法还原。文件格式（UTF-8 文本，行式 key=value）：</p>
 *
 * <pre>
 *   version=1
 *   name=mydb-key              # 用户指定的工作密钥名称
 *   rootKeyId=order-2026       # 加密它的根密钥 keyId（归属核对）
 *   rootKcv=2df4d28e...        # 根密钥 KCV（核对用，不泄露密钥）
 *   algorithm=AES
 *   kcv=5c1e...                # 工作密钥自身的 KCV（还原后自证）
 *   wrapped=&lt;Base64(RK01信封：IV+GCM密文+Tag)，明文为 32 字节工作密钥&gt;
 *   checksum=&lt;64位十六进制，覆盖上述全部字段&gt;
 * </pre>
 */
public final class WorkKeyFile {

    private final int version;
    private final String name;
    private final String rootKeyId;
    private final String rootKcvHex;
    private final String kcvHex;
    private final byte[] wrapped;

    private WorkKeyFile(int version, String name, String rootKeyId,
                        String rootKcvHex, String kcvHex, byte[] wrapped) {
        this.version = version;
        this.name = name;
        this.rootKeyId = rootKeyId;
        this.rootKcvHex = rootKcvHex.toLowerCase();
        this.kcvHex = kcvHex.toLowerCase();
        this.wrapped = wrapped.clone();
    }

    public static WorkKeyFile create(String name, String rootKeyId, String rootKcvHex,
                                     String kcvHex, byte[] wrapped) {
        if (name == null || !RootKeyConstants.NAME_PATTERN.matcher(name).matches()) {
            throw new RootKeyException("非法工作密钥名称: '" + name + "'（仅允许 1-64 位字母/数字/./_/-）");
        }
        if (rootKeyId == null || !RootKeyConstants.NAME_PATTERN.matcher(rootKeyId).matches()) {
            throw new RootKeyException("非法 rootKeyId: '" + rootKeyId + "'");
        }
        if (rootKcvHex == null || !rootKcvHex.matches("^[0-9a-fA-F]{16}$")) {
            throw new RootKeyException("非法 rootKcv");
        }
        if (kcvHex == null || !kcvHex.matches("^[0-9a-fA-F]{16}$")) {
            throw new RootKeyException("非法工作密钥 kcv");
        }
        // 最小长度：RK01 信封 = 3B 头 + 12B IV + 16B Tag，密文体可为 0
        if (wrapped == null || wrapped.length < 31) {
            throw new RootKeyException("wrapped 密文长度非法（最小 31 字节）");
        }
        return new WorkKeyFile(RootKeyConstants.FILE_FORMAT_VERSION, name, rootKeyId,
                rootKcvHex, kcvHex, wrapped);
    }

    /** 从文件加载并完整校验（格式/长度/checksum） */
    public static WorkKeyFile load(Path path) {
        List<String> lines;
        try {
            lines = Files.readAllLines(path, StandardCharsets.UTF_8);
        } catch (IOException e) {
            throw new RootKeyException("无法读取工作密钥文件: " + path, e);
        }
        Map<String, String> map = new LinkedHashMap<String, String>();
        for (String raw : lines) {
            String line = raw.trim();
            if (line.isEmpty() || line.startsWith("#")) {
                continue;
            }
            int eq = line.indexOf('=');
            if (eq <= 0) {
                throw new RootKeyException("工作密钥文件格式错误: " + path + " -> \"" + line + "\"");
            }
            if (map.put(line.substring(0, eq).trim(), line.substring(eq + 1).trim()) != null) {
                throw new RootKeyException("工作密钥文件存在重复字段 '" + line.substring(0, eq).trim() + "': " + path);
            }
        }
        for (String required : new String[]{"version", "name", "rootKeyId", "rootKcv", "algorithm", "kcv", "wrapped", "checksum"}) {
            if (!map.containsKey(required)) {
                throw new RootKeyException("工作密钥文件缺少字段 '" + required + "': " + path);
            }
        }
        int version;
        try {
            version = Integer.parseInt(map.get("version"));
        } catch (NumberFormatException e) {
            throw new RootKeyException("工作密钥文件 version 非法: " + path);
        }
        if (version != RootKeyConstants.FILE_FORMAT_VERSION) {
            throw new RootKeyException("工作密钥文件版本不支持 (" + version + "): " + path);
        }
        if (!RootKeyConstants.ALGORITHM.equals(map.get("algorithm"))) {
            throw new RootKeyException("工作密钥 algorithm 非法: '" + map.get("algorithm") + "': " + path);
        }
        WorkKeyFile wf = new WorkKeyFile(version, map.get("name"), map.get("rootKeyId"),
                map.get("rootKcv"), map.get("kcv"),
                decodeWrapped(map.get("wrapped"), path));
        if (!wf.checksumHex().equalsIgnoreCase(map.get("checksum"))) {
            throw new RootKeyException("工作密钥文件校验和不匹配（文件可能被篡改或损坏）: " + path
                    + "，期望 " + wf.checksumHex() + "，实际 " + map.get("checksum").toLowerCase());
        }
        return wf;
    }

    private static byte[] decodeWrapped(String b64, Path path) {
        byte[] wrapped;
        try {
            wrapped = Base64.getDecoder().decode(b64 == null ? "" : b64);
        } catch (IllegalArgumentException e) {
            throw new RootKeyException("工作密钥 wrapped 不是合法 Base64: " + path);
        }
        if (wrapped.length < 31) {
            throw new RootKeyException("工作密钥 wrapped 长度非法: " + path);
        }
        return wrapped;
    }

    /** 校验和覆盖的规范串 */
    String canonical() {
        return version + "|" + name + "|" + rootKeyId + "|" + rootKcvHex
                + "|" + kcvHex + "|" + Codec.b64(wrapped);
    }

    public String checksumHex() {
        return Codec.sha256Hex(canonical());
    }

    public String serialize() {
        StringBuilder sb = new StringBuilder(400);
        sb.append("# RootKey 工作密钥文件（已被根密钥加密；泄露本文件不会泄露密钥，但请妥善保管）\n");
        sb.append("# name=").append(name).append(" rootKeyId=").append(rootKeyId).append('\n');
        sb.append("version=").append(version).append('\n');
        sb.append("name=").append(name).append('\n');
        sb.append("rootKeyId=").append(rootKeyId).append('\n');
        sb.append("rootKcv=").append(rootKcvHex).append('\n');
        sb.append("algorithm=").append(RootKeyConstants.ALGORITHM).append('\n');
        sb.append("kcv=").append(kcvHex).append('\n');
        sb.append("wrapped=").append(Codec.b64(wrapped)).append('\n');
        sb.append("checksum=").append(checksumHex()).append('\n');
        return sb.toString();
    }

    /** 保存到文件（权限尽力设为 600） */
    public void save(Path path) {
        try {
            Files.write(path, serialize().getBytes(StandardCharsets.UTF_8),
                    java.nio.file.StandardOpenOption.CREATE,
                    java.nio.file.StandardOpenOption.TRUNCATE_EXISTING,
                    java.nio.file.StandardOpenOption.WRITE);
        } catch (IOException e) {
            throw new RootKeyException("无法写入工作密钥文件: " + path, e);
        }
        try {
            Files.setPosixFilePermissions(path, PosixFilePermissions.fromString("rw-------"));
        } catch (Exception ignore) {
            // 非 POSIX 文件系统跳过
        }
    }

    public int version() {
        return version;
    }

    public String name() {
        return name;
    }

    public String rootKeyId() {
        return rootKeyId;
    }

    public String rootKcvHex() {
        return rootKcvHex;
    }

    public String kcvHex() {
        return kcvHex;
    }

    /** 被根密钥加密的密钥材料（返回副本） */
    public byte[] wrapped() {
        return wrapped.clone();
    }
}
