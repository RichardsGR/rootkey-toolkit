package com.metrace.rootkey.workkey;

import com.metrace.rootkey.RootKeyConstants;
import com.metrace.rootkey.RootKeyException;
import com.metrace.rootkey.internal.Codec;
import com.metrace.rootkey.internal.Json;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.attribute.PosixFilePermissions;
import java.util.ArrayList;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * 工作密钥文件：被根密钥加密后的 WorkKey 落盘载体（信封加密的"信封"）。
 *
 * <p>JSON 格式，一个文件可存放<b>多个</b>工作密钥。文件可存放在业务侧——
 * 其中只有被 AES-256-GCM 加密的密钥材料，没有根密钥四组件无法还原：</p>
 *
 * <pre>
 * {
 *   "version": 1,
 *   "rootKeyId": "biz-root-2026",
 *   "rootKcv": "508b80c5...",
 *   "keys": [
 *     { "name": "order-db", "algorithm": "AES", "kcv": "...", "wrapped": "...", "checksum": "..." }
 *   ]
 * }
 * </pre>
 *
 * <p>每个条目的 checksum 覆盖 name/rootKeyId/rootKcv/kcv/wrapped，
 * 任何字段被篡改都会在加载时被发现。</p>
 */
public final class WorkKeyFile {

    private final int version;
    private final String rootKeyId;
    private final String rootKcvHex;
    private final List<Entry> keys;

    /** 文件内的单个工作密钥条目 */
    public static final class Entry {
        private final String name;
        private final String kcvHex;
        private final byte[] wrapped;
        private final String checksumHex;

        private Entry(String name, String rootKeyId, String rootKcvHex, String kcvHex, byte[] wrapped) {
            this.name = name;
            this.kcvHex = kcvHex.toLowerCase();
            this.wrapped = wrapped.clone();
            // checksum 覆盖全部业务字段（含根密钥归属），改任何一处都会被发现
            this.checksumHex = Codec.sha256Hex("1|" + name + "|" + rootKeyId + "|" + rootKcvHex.toLowerCase()
                    + "|" + kcvHex.toLowerCase() + "|" + Codec.b64(wrapped));
        }

        private Entry(String name, String kcvHex, byte[] wrapped, String checksumHex) {
            this.name = name;
            this.kcvHex = kcvHex.toLowerCase();
            this.wrapped = wrapped;
            this.checksumHex = checksumHex;
        }

        public String name() {
            return name;
        }

        public String kcvHex() {
            return kcvHex;
        }

        public byte[] wrapped() {
            return wrapped.clone();
        }

        String checksumHex() {
            return checksumHex;
        }

        Map<String, Object> toJson() {
            Map<String, Object> m = new LinkedHashMap<String, Object>();
            m.put("name", name);
            m.put("algorithm", RootKeyConstants.ALGORITHM);
            m.put("kcv", kcvHex);
            m.put("wrapped", Codec.b64(wrapped));
            m.put("checksum", checksumHex);
            return m;
        }
    }

    private WorkKeyFile(int version, String rootKeyId, String rootKcvHex, List<Entry> keys) {
        this.version = version;
        this.rootKeyId = rootKeyId;
        this.rootKcvHex = rootKcvHex.toLowerCase();
        this.keys = keys;
    }

    /** 创建空文件对象（再通过 {@link #add} 追加条目） */
    public static WorkKeyFile create(String rootKeyId, String rootKcvHex) {
        validateRootFields(rootKeyId, rootKcvHex);
        return new WorkKeyFile(RootKeyConstants.FILE_FORMAT_VERSION, rootKeyId, rootKcvHex,
                new ArrayList<Entry>());
    }

    private static void validateRootFields(String rootKeyId, String rootKcvHex) {
        if (rootKeyId == null || !RootKeyConstants.NAME_PATTERN.matcher(rootKeyId).matches()) {
            throw new RootKeyException("非法 rootKeyId: '" + rootKeyId + "'");
        }
        if (rootKcvHex == null || !rootKcvHex.matches("^[0-9a-fA-F]{16}$")) {
            throw new RootKeyException("非法 rootKcv");
        }
    }

    /** 构造条目（自动计算 checksum） */
    public static Entry entry(String name, String rootKeyId, String rootKcvHex, String kcvHex, byte[] wrapped) {
        validateName(name);
        if (kcvHex == null || !kcvHex.matches("^[0-9a-fA-F]{16}$")) {
            throw new RootKeyException("非法工作密钥 kcv: '" + kcvHex + "'");
        }
        // 最小长度：RK01 信封 = 3B 头 + 12B IV + 16B Tag，密文体可为 0
        if (wrapped == null || wrapped.length < 31) {
            throw new RootKeyException("wrapped 密文长度非法（最小 31 字节）");
        }
        return new Entry(name, rootKeyId, rootKcvHex, kcvHex, wrapped);
    }

    private static void validateName(String name) {
        if (name == null || !RootKeyConstants.NAME_PATTERN.matcher(name).matches()) {
            throw new RootKeyException("非法工作密钥名称: '" + name + "'（仅允许 1-64 位字母/数字/./_/-）");
        }
    }

    /** 追加条目；同名条目已存在时抛错 */
    public void add(Entry e) {
        if (hasEntry(e.name())) {
            throw new RootKeyException("文件中已存在同名工作密钥 '" + e.name() + "'");
        }
        keys.add(e);
    }

    /** 替换或追加条目 */
    public void put(Entry e) {
        for (int i = 0; i < keys.size(); i++) {
            if (keys.get(i).name().equals(e.name())) {
                keys.set(i, e);
                return;
            }
        }
        keys.add(e);
    }

    public boolean hasEntry(String name) {
        return findEntry(name) != null;
    }

    /** 按名称取条目；不存在时抛错并附上现有名称列表 */
    public Entry getEntry(String name) {
        Entry e = findEntry(name);
        if (e == null) {
            throw new RootKeyException("工作密钥文件中不存在 '" + name + "'，现有: " + names());
        }
        return e;
    }

    private Entry findEntry(String name) {
        for (Entry e : keys) {
            if (e.name().equals(name)) {
                return e;
            }
        }
        return null;
    }

    /** 文件内全部条目名称（按存放顺序） */
    public List<String> names() {
        List<String> out = new ArrayList<String>();
        for (Entry e : keys) {
            out.add(e.name());
        }
        return out;
    }

    public int keyCount() {
        return keys.size();
    }

    // ------------------------------------------------------------------ 序列化

    public String serialize() {
        Map<String, Object> root = new LinkedHashMap<String, Object>();
        root.put("version", version);
        root.put("rootKeyId", rootKeyId);
        root.put("rootKcv", rootKcvHex);
        List<Object> arr = new ArrayList<Object>();
        for (Entry e : keys) {
            arr.add(e.toJson());
        }
        root.put("keys", arr);
        StringBuilder sb = new StringBuilder(512);
        sb.append("# RootKey 工作密钥文件（已被根密钥加密；泄露本文件不会泄露密钥，但请妥善保管）\n");
        sb.append(Json.write(root)).append('\n');
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

    // ------------------------------------------------------------------ 加载

    @SuppressWarnings("unchecked")
    public static WorkKeyFile load(Path path) {
        String text;
        try {
            text = new String(Files.readAllBytes(path), StandardCharsets.UTF_8);
        } catch (IOException e) {
            throw new RootKeyException("无法读取工作密钥文件: " + path, e);
        }
        // 允许首行注释
        String jsonText = stripCommentLines(text);
        Object parsed;
        try {
            parsed = Json.parse(jsonText);
        } catch (RuntimeException e) {
            throw new RootKeyException("工作密钥文件不是合法 JSON: " + path + "（" + e.getMessage() + "）");
        }
        if (!(parsed instanceof Map)) {
            throw new RootKeyException("工作密钥文件顶层必须是 JSON 对象: " + path);
        }
        Map<String, Object> root = (Map<String, Object>) parsed;
        int version = intField(root, "version", path);
        if (version != RootKeyConstants.FILE_FORMAT_VERSION) {
            throw new RootKeyException("工作密钥文件版本不支持 (" + version + "): " + path);
        }
        String rootKeyId = strField(root, "rootKeyId", path);
        String rootKcv = strField(root, "rootKcv", path);
        validateRootFields(rootKeyId, rootKcv);

        Object keysObj = root.get("keys");
        if (!(keysObj instanceof List) || ((List<Object>) keysObj).isEmpty()) {
            throw new RootKeyException("工作密钥文件 keys 必须是非空数组: " + path);
        }
        List<Entry> entries = new ArrayList<Entry>();
        for (Object o : (List<Object>) keysObj) {
            if (!(o instanceof Map)) {
                throw new RootKeyException("工作密钥条目必须是 JSON 对象: " + path);
            }
            Map<String, Object> m = (Map<String, Object>) o;
            String name = strField(m, "name", path);
            validateName(name);
            if (!RootKeyConstants.ALGORITHM.equals(strField(m, "algorithm", path))) {
                throw new RootKeyException("工作密钥 '" + name + "' algorithm 非法（仅支持 AES）: " + path);
            }
            String kcv = strField(m, "kcv", path);
            byte[] wrapped = decodeWrapped(strField(m, "wrapped", path), path, name);
            String checksum = strField(m, "checksum", path);
            // 从字段重算 checksum 再比对（不能拿文件里的存值自证）
            String expected = Codec.sha256Hex("1|" + name + "|" + rootKeyId + "|" + rootKcv.toLowerCase()
                    + "|" + kcv.toLowerCase() + "|" + Codec.b64(wrapped));
            if (!expected.equalsIgnoreCase(checksum)) {
                throw new RootKeyException("工作密钥 '" + name + "' 校验和不匹配（可能被篡改或损坏）: " + path
                        + "，期望 " + expected + "，实际 " + checksum.toLowerCase());
            }
            entries.add(new Entry(name, rootKeyId, rootKcv, kcv, wrapped));
        }
        // 名称唯一性
        for (int i = 0; i < entries.size(); i++) {
            for (int j = i + 1; j < entries.size(); j++) {
                if (entries.get(i).name().equals(entries.get(j).name())) {
                    throw new RootKeyException("工作密钥文件存在重复名称 '" + entries.get(i).name() + "': " + path);
                }
            }
        }
        return new WorkKeyFile(version, rootKeyId, rootKcv, entries);
    }

    private static String stripCommentLines(String text) {
        // 跳过以 # 开头的行（JSON 本身不会以 # 开头）
        StringBuilder sb = new StringBuilder(text.length());
        for (String line : text.split("\n", -1)) {
            String t = line.trim();
            if (t.isEmpty() || t.startsWith("#")) {
                continue;
            }
            sb.append(line).append('\n');
        }
        return sb.toString();
    }

    private static int intField(Map<String, Object> m, String key, Path path) {
        Object v = m.get(key);
        if (!(v instanceof Number)) {
            throw new RootKeyException("工作密钥文件缺少数字字段 '" + key + "': " + path);
        }
        return ((Number) v).intValue();
    }

    private static String strField(Map<String, Object> m, String key, Path path) {
        Object v = m.get(key);
        if (!(v instanceof String) || ((String) v).trim().isEmpty()) {
            throw new RootKeyException("工作密钥文件缺少字符串字段 '" + key + "': " + path);
        }
        return (String) v;
    }

    private static byte[] decodeWrapped(String b64, Path path, String name) {
        byte[] wrapped;
        try {
            wrapped = Base64.getDecoder().decode(b64);
        } catch (IllegalArgumentException e) {
            throw new RootKeyException("工作密钥 '" + name + "' wrapped 不是合法 Base64: " + path);
        }
        if (wrapped.length < 31) {
            throw new RootKeyException("工作密钥 '" + name + "' wrapped 长度非法: " + path);
        }
        return wrapped;
    }

    public int version() {
        return version;
    }

    public String rootKeyId() {
        return rootKeyId;
    }

    public String rootKcvHex() {
        return rootKcvHex;
    }

    /** 文件内全部条目（只读视图语义：返回副本列表，Entry 不可变） */
    public List<Entry> entries() {
        return new ArrayList<Entry>(keys);
    }
}
