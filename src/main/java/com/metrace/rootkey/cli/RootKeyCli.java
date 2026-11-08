package com.metrace.rootkey.cli;

import com.metrace.rootkey.RootKeyConstants;
import com.metrace.rootkey.RootKeyException;
import com.metrace.rootkey.RootKeyManager;
import com.metrace.rootkey.config.RootKeyConfig;
import com.metrace.rootkey.core.ComponentFile;
import com.metrace.rootkey.core.RootKeyGenerator;
import com.metrace.rootkey.core.RootKeyRestorer;
import com.metrace.rootkey.core.RootKeySecret;
import com.metrace.rootkey.internal.Codec;

import java.io.FileDescriptor;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.io.PrintStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Properties;

/**
 * 本地管理工具入口（与 SDK 同一 jar）：
 *
 * <pre>
 *   generate  生成根密钥四组件（本地操作，生成后分发给服务器）
 *   verify    校验组件完整性并试还原
 *   restore   还原根密钥（仅显示 KCV，绝不输出密钥本体）
 *   encrypt   还原密钥后加密
 *   decrypt   还原密钥后解密
 * </pre>
 */
public final class RootKeyCli {

    public static void main(String[] args) {
        int code;
        try {
            code = run(args);
        } catch (UsageException e) {
            System.err.println(e.getMessage());
            printUsage(System.err);
            code = 2;
        } catch (RootKeyException e) {
            System.err.println("[错误] " + e.getMessage());
            code = 1;
        } catch (Exception e) {
            System.err.println("[异常] " + e);
            e.printStackTrace();
            code = 1;
        }
        System.exit(code);
    }

    private static int run(String[] args) throws IOException {
        if (args.length == 0) {
            printUsage(System.out);
            return 0;
        }
        String cmd = args[0];
        String[] rest = Arrays.copyOfRange(args, 1, args.length);
        if ("generate".equals(cmd)) {
            return cmdGenerate(rest);
        }
        if ("verify".equals(cmd) || "restore".equals(cmd)) {
            return cmdVerifyRestore(cmd, rest);
        }
        if ("encrypt".equals(cmd) || "decrypt".equals(cmd)) {
            return cmdEncryptDecrypt(cmd, rest);
        }
        if ("ui".equals(cmd)) {
            return cmdUi(rest);
        }
        if ("workkey".equals(cmd)) {
            return cmdWorkKey(rest);
        }
        if ("client".equals(cmd)) {
            // 打开桌面客户端窗口；挂住主线程，直到窗口关闭触发 EXIT_ON_CLOSE 整体退出
            com.metrace.rootkey.client.RootKeyClient.main(rest);
            try {
                Thread.currentThread().join();
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
            }
            return 0;
        }
        if ("help".equals(cmd) || "--help".equals(cmd) || "-h".equals(cmd)) {
            printUsage(System.out);
            return 0;
        }
        throw new UsageException("未知命令: " + cmd);
    }

    // ------------------------------------------------------------------ generate

    private static int cmdGenerate(String[] args) throws IOException {
        String out = "rootkey-components";
        String keyId = null;
        boolean force = false;
        for (int i = 0; i < args.length; i++) {
            String a = args[i];
            if ("--out".equals(a)) {
                out = requireValue(args, ++i, a);
            } else if ("--key-id".equals(a)) {
                keyId = requireValue(args, ++i, a);
            } else if ("--force".equals(a)) {
                force = true;
            } else {
                throw new UsageException("generate 不认识参数: " + a);
            }
        }
        if (keyId == null) {
            keyId = RootKeyGenerator.defaultKeyId();
        }
        Path outDir = Paths.get(out).toAbsolutePath().normalize();
        try (RootKeyGenerator.GenerateResult r = RootKeyManager.generate(outDir, keyId, force)) {
            System.out.println("根密钥生成成功（密钥本体未落盘）");
            System.out.println("  keyId     : " + r.keyId());
            System.out.println("  KCV       : " + r.kcvHex());
            List<String> names = Arrays.asList("a", "b", "c", "d");
            List<Path> paths = r.componentPaths();
            for (int i = 0; i < paths.size(); i++) {
                System.out.println("  组件 " + names.get(i) + "     : " + paths.get(i)
                        + " (" + Files.size(paths.get(i)) + " 字节)");
            }
            System.out.println("  manifest  : " + r.manifestPath());
            System.out.println("请将四个组件分别存放于不同的安全位置（不同目录/主机/权限），并分别备份。");
            System.out.println("组件可安全地分批拷贝传输，但四者同时泄露即等于根密钥泄露。");
        }
        return 0;
    }

    // ------------------------------------------------------------------ verify / restore

    private static int cmdVerifyRestore(String cmd, String[] args) throws IOException {
        List<String> positional = new ArrayList<String>();
        String configPath = null;
        for (int i = 0; i < args.length; i++) {
            String a = args[i];
            if ("--config".equals(a)) {
                configPath = requireValue(args, ++i, a);
            } else if (a.startsWith("--")) {
                throw new UsageException(cmd + " 不认识参数: " + a);
            } else {
                positional.add(a);
            }
        }
        List<Path> paths = configPath != null
                ? componentPathsFromConfig(configPath)
                : resolveComponents(positional, "verify/restore");
        List<ComponentFile> comps = new ArrayList<ComponentFile>();
        for (Path p : paths) {
            ComponentFile cf = ComponentFile.load(p);
            comps.add(cf);
            System.out.println("  [OK] " + p + " (组件 " + cf.label() + ", keyId=" + cf.keyId()
                    + ", checksum 通过)");
        }
        RootKeySecret secret = RootKeyRestorer.restoreFiles(comps);
        System.out.println("  [OK] 标签/一致性/KCV 全部校验通过");
        if ("verify".equals(cmd)) {
            Path dir = paths.get(0).getParent();
            Path manifest = dir == null ? null : dir.resolve("manifest.properties");
            if (manifest != null && Files.isReadable(manifest)) {
                Properties props = new Properties();
                try (java.io.Reader reader = Files.newBufferedReader(manifest, java.nio.charset.StandardCharsets.UTF_8)) {
                    props.load(reader);
                }
                String mKcv = props.getProperty("kcv", "").toLowerCase();
                if (mKcv.equals(secret.kcvHex())) {
                    System.out.println("  [OK] 与 manifest 中记录的 KCV 一致");
                } else {
                    throw new RootKeyException("manifest 中记录的 KCV (" + mKcv + ") 与还原结果 ("
                            + secret.kcvHex() + ") 不一致");
                }
            }
        }
        System.out.println("根密钥还原成功: keyId=" + secret.keyId() + ", KCV=" + secret.kcvHex()
                + "（密钥本体不会输出）");
        secret.destroy();
        return 0;
    }

    // ------------------------------------------------------------------ encrypt / decrypt

    private static int cmdEncryptDecrypt(String cmd, String[] args) throws IOException {
        String in = null;
        String out = null;
        String configPath = null;
        boolean base64 = false;
        List<String> positional = new ArrayList<String>();
        for (int i = 0; i < args.length; i++) {
            String a = args[i];
            if ("--in".equals(a)) {
                in = requireValue(args, ++i, a);
            } else if ("--out".equals(a)) {
                out = requireValue(args, ++i, a);
            } else if ("--config".equals(a)) {
                configPath = requireValue(args, ++i, a);
            } else if ("--base64".equals(a)) {
                base64 = true;
            } else if (a.startsWith("--")) {
                throw new UsageException(cmd + " 不认识参数: " + a);
            } else {
                positional.add(a);
            }
        }

        RootKeyConfig cfg;
        if (configPath != null) {
            cfg = RootKeyConfig.load(Paths.get(configPath));
        } else {
            cfg = rootConfigFromPositional(positional, cmd);
        }

        byte[] input = readInput(in);
        boolean isEncrypt = "encrypt".equals(cmd);
        try (RootKeyManager km = new RootKeyManager(cfg)) {
            byte[] data;
            if (isEncrypt) {
                data = km.encrypt(input);
            } else {
                byte[] ciphertext = base64 ? decodeBase64(input) : input;
                data = km.decrypt(ciphertext);
            }
            // --base64 仅作用于密文侧：加密输出 Base64，解密输入按 Base64 解码；明文始终原样输出
            writeOutput(out, data, isEncrypt && base64);
            System.err.println("[INFO] " + (isEncrypt ? "加密" : "解密") + "完成 (keyId="
                    + km.keyId() + ", KCV=" + km.kcv() + ", " + input.length + " 字节输入)");
        }
        return 0;
    }

    /** Base64 文本（容忍首尾空白/换行）解回二进制 */
    private static byte[] decodeBase64(byte[] text) {
        String s = new String(text, java.nio.charset.StandardCharsets.UTF_8).trim();
        try {
            return java.util.Base64.getDecoder().decode(s);
        } catch (IllegalArgumentException e) {
            throw new RootKeyException("输入不是合法的 Base64 密文");
        }
    }

    // ------------------------------------------------------------------ workkey

    private static int cmdWorkKey(String[] args) throws IOException {
        if (args.length == 0) {
            throw new UsageException("workkey 需要 gen / restore / encrypt / decrypt / list 子命令");
        }
        String sub = args[0];
        String[] rest = Arrays.copyOfRange(args, 1, args.length);
        if ("gen".equals(sub) || "generate".equals(sub)) {
            return wkGenerate(rest);
        }
        if ("restore".equals(sub) || "verify".equals(sub)) {
            return wkRestore(rest);
        }
        if ("encrypt".equals(sub) || "decrypt".equals(sub)) {
            return wkCrypt(sub, rest);
        }
        if ("list".equals(sub)) {
            return wkList(rest);
        }
        throw new UsageException("未知 workkey 子命令: " + sub);
    }

    /** workkey gen：位置参数 = 根密钥组件（目录或 4 文件），选项 --name --out --force；文件已存在则为追加 */
    private static int wkGenerate(String[] args) throws IOException {
        String name = null;
        String out = null;
        boolean force = false;
        List<String> positional = new ArrayList<String>();
        for (int i = 0; i < args.length; i++) {
            String a = args[i];
            if ("--name".equals(a)) {
                name = requireValue(args, ++i, a);
            } else if ("--out".equals(a)) {
                out = requireValue(args, ++i, a);
            } else if ("--force".equals(a)) {
                force = true;
            } else if (a.startsWith("--")) {
                throw new UsageException("workkey gen 不认识参数: " + a);
            } else {
                positional.add(a);
            }
        }
        if (name == null || name.trim().isEmpty()) {
            throw new UsageException("workkey gen 需要 --name <工作密钥名称>");
        }
        Path outFile = out == null
                ? Paths.get(name.trim() + com.metrace.rootkey.RootKeyConstants.WORKKEY_FILE_SUFFIX)
                : Paths.get(out);
        try (RootKeyManager root = new RootKeyManager(rootConfigFromPositional(positional, "workkey gen"));
             com.metrace.rootkey.workkey.WorkKeyManager.Generated g =
                     com.metrace.rootkey.workkey.WorkKeyManager.generate(outFile, name.trim(), root, force)) {
            System.out.println("工作密钥生成成功（已用根密钥加密落盘）");
            System.out.println("  名称    : " + g.name());
            System.out.println("  KCV     : " + g.kcvHex());
            System.out.println("  文件    : " + g.file());
            System.out.println("  根密钥  : keyId=" + root.keyId() + ", KCV=" + root.kcv());
            System.out.println("  文件内现有密钥: " + g.namesInFile());
            System.out.println("该 .json 文件可放入业务侧（可存多个工作密钥）；没有根密钥四组件无法还原。");
        }
        return 0;
    }

    /** workkey restore：位置参数 = 根密钥组件，选项 --workkey <文件> [--name <名称>] */
    private static int wkRestore(String[] args) throws IOException {
        String wk = null;
        String name = null;
        List<String> positional = new ArrayList<String>();
        for (int i = 0; i < args.length; i++) {
            String a = args[i];
            if ("--workkey".equals(a)) {
                wk = requireValue(args, ++i, a);
            } else if ("--name".equals(a)) {
                name = requireValue(args, ++i, a);
            } else if (a.startsWith("--")) {
                throw new UsageException("workkey restore 不认识参数: " + a);
            } else {
                positional.add(a);
            }
        }
        try (RootKeyManager root = new RootKeyManager(rootConfigFromPositional(positional, "workkey restore"));
             com.metrace.rootkey.workkey.WorkKeySecret s =
                     com.metrace.rootkey.workkey.WorkKeyManager.restore(Paths.get(wk), name, root)) {
            System.out.println("工作密钥还原成功（密钥本体不会输出）");
            System.out.println("  名称      : " + s.name());
            System.out.println("  KCV       : " + s.kcvHex());
            System.out.println("  根密钥    : keyId=" + root.keyId() + ", KCV=" + root.kcv());
        }
        return 0;
    }

    /** workkey encrypt/decrypt：位置参数 = 根密钥组件，选项 --workkey [--name] --in --out --base64 */
    private static int wkCrypt(String sub, String[] args) throws IOException {
        String in = null;
        String out = null;
        String wk = null;
        String name = null;
        boolean base64 = false;
        List<String> positional = new ArrayList<String>();
        for (int i = 0; i < args.length; i++) {
            String a = args[i];
            if ("--in".equals(a)) {
                in = requireValue(args, ++i, a);
            } else if ("--out".equals(a)) {
                out = requireValue(args, ++i, a);
            } else if ("--workkey".equals(a)) {
                wk = requireValue(args, ++i, a);
            } else if ("--name".equals(a)) {
                name = requireValue(args, ++i, a);
            } else if ("--base64".equals(a)) {
                base64 = true;
            } else if (a.startsWith("--")) {
                throw new UsageException("workkey " + sub + " 不认识参数: " + a);
            } else {
                positional.add(a);
            }
        }
        boolean isEncrypt = "encrypt".equals(sub);
        byte[] input = readInput(in);
        try (RootKeyManager root = new RootKeyManager(rootConfigFromPositional(positional, "workkey " + sub));
             com.metrace.rootkey.workkey.WorkKeyManager wkm =
                     new com.metrace.rootkey.workkey.WorkKeyManager(root, Paths.get(wk), name)) {
            byte[] data;
            if (isEncrypt) {
                data = wkm.encrypt(input);
            } else {
                data = wkm.decrypt(base64 ? decodeBase64(input) : input);
            }
            // --base64 仅作用于密文侧（与根密钥加解密语义一致）
            writeOutput(out, data, isEncrypt && base64);
            System.err.println("[INFO] 工作密钥" + (isEncrypt ? "加密" : "解密") + "完成 (name="
                    + wkm.name() + ", KCV=" + wkm.kcv() + ", " + input.length + " 字节输入)");
        }
        return 0;
    }

    /** workkey list：列出 .json 文件内全部工作密钥（名称/KCV，无需根密钥） */
    private static int wkList(String[] args) throws IOException {
        String wk = null;
        for (int i = 0; i < args.length; i++) {
            String a = args[i];
            if ("--workkey".equals(a)) {
                wk = requireValue(args, ++i, a);
            } else {
                throw new UsageException("workkey list 只支持 --workkey <文件>");
            }
        }
        com.metrace.rootkey.workkey.WorkKeyFile f =
                com.metrace.rootkey.workkey.WorkKeyFile.load(Paths.get(wk));
        System.out.println("文件    : " + Paths.get(wk).toAbsolutePath().normalize());
        System.out.println("根密钥  : keyId=" + f.rootKeyId() + ", KCV=" + f.rootKcvHex());
        System.out.println("密钥数  : " + f.keyCount());
        for (com.metrace.rootkey.workkey.WorkKeyFile.Entry e : f.entries()) {
            System.out.println("  - " + e.name() + "  (KCV=" + e.kcvHex() + ")");
        }
        return 0;
    }

    // ------------------------------------------------------------------ ui

    /** 启动本地 Web 管理页面（仅监听 127.0.0.1） */
    private static int cmdUi(String[] args) throws IOException {
        int port = 8765;
        for (int i = 0; i < args.length; i++) {
            String a = args[i];
            if ("--port".equals(a)) {
                String v = requireValue(args, ++i, a);
                try {
                    port = Integer.parseInt(v);
                } catch (NumberFormatException e) {
                    throw new UsageException("--port 需要数字，收到: " + v);
                }
            } else {
                throw new UsageException("ui 不认识参数: " + a);
            }
        }
        com.metrace.rootkey.webui.WebUiServer server;
        try {
            server = new com.metrace.rootkey.webui.WebUiServer(port);
        } catch (IOException e) {
            throw new RootKeyException("无法在 127.0.0.1:" + port + " 启动管理页面（端口被占用？可用 --port 换一个）", e);
        }
        server.start();
        System.out.println("RootKey 管理台已启动: http://127.0.0.1:" + server.port());
        System.out.println("仅监听 127.0.0.1（本机可访问）；Ctrl-C 退出。");
        // WebUiServer 线程均为守护线程，主线程挂住保活
        try {
            Thread.currentThread().join();
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        }
        server.stop();
        return 0;
    }

    // ------------------------------------------------------------------ helpers

    /** 从配置文件取四个组件路径 */
    private static List<Path> componentPathsFromConfig(String configPath) {
        RootKeyConfig cfg = RootKeyConfig.load(Paths.get(configPath));
        List<Path> paths = new ArrayList<Path>();
        paths.add(cfg.aPath());
        paths.add(cfg.bPath());
        paths.add(cfg.cPath());
        paths.add(cfg.dPath());
        List<String> missing = new ArrayList<String>();
        for (Path p : paths) {
            if (!java.nio.file.Files.isReadable(p)) {
                missing.add(p.toString());
            }
        }
        if (!missing.isEmpty()) {
            throw new RootKeyException("组件文件不存在或不可读: " + String.join(", ", missing));
        }
        return paths;
    }

    /** 从位置参数解析根密钥组件（1 个目录或 4 个文件）并构建配置 */
    private static RootKeyConfig rootConfigFromPositional(List<String> positional, String cmd) {
        List<Path> comps = resolveComponents(positional, cmd);
        return RootKeyConfig.builder()
                .a(comps.get(0)).b(comps.get(1)).c(comps.get(2)).d(comps.get(3)).build();
    }

    /**
     * 解析组件位置：1 个参数视为目录（内含 a/b/c/d.txt），4 个参数视为四个文件。
     */
    private static List<Path> resolveComponents(List<String> positional, String cmd) {
        if (positional.size() != 1 && positional.size() != 4) {
            throw new UsageException(cmd + " 需要一个组件目录，或 a b c d 四个组件文件路径");
        }
        List<Path> paths = new ArrayList<Path>();
        if (positional.size() == 1) {
            Path dir = Paths.get(positional.get(0));
            for (char label : RootKeyConstants.COMPONENT_LABELS) {
                paths.add(dir.resolve(label + RootKeyConstants.COMPONENT_FILE_SUFFIX));
            }
        } else {
            for (String p : positional) {
                paths.add(Paths.get(p));
            }
        }
        List<String> missing = new ArrayList<String>();
        for (Path p : paths) {
            if (!Files.isReadable(p)) {
                missing.add(p.toString());
            }
        }
        if (!missing.isEmpty()) {
            throw new RootKeyException("组件文件不存在或不可读: " + String.join(", ", missing));
        }
        return paths;
    }

    private static String requireValue(String[] args, int index, String flag) {
        if (index >= args.length) {
            throw new UsageException("参数 " + flag + " 缺少取值");
        }
        return args[index];
    }

    private static byte[] readInput(String in) throws IOException {
        InputStream source;
        if (in == null || "-".equals(in)) {
            source = System.in;
        } else {
            source = Files.newInputStream(Paths.get(in));
        }
        try {
            return Codec.readAll(source);
        } finally {
            if (source != System.in) {
                source.close();
            }
        }
    }

    private static void writeOutput(String out, byte[] data, boolean base64) throws IOException {
        if (base64) {
            String text = Codec.b64(data) + "\n";
            if (out == null || "-".equals(out)) {
                System.out.print(text);
            } else {
                Files.write(Paths.get(out), text.getBytes(java.nio.charset.StandardCharsets.UTF_8));
            }
            return;
        }
        OutputStream sink = (out == null || "-".equals(out))
                ? new FileOutputStream(FileDescriptor.out)
                : Files.newOutputStream(Paths.get(out));
        try {
            sink.write(data);
            sink.flush();
        } finally {
            if (!(sink instanceof FileOutputStream) || out != null) {
                sink.close();
            }
        }
    }

    private static void printUsage(PrintStream ps) {
        ps.println("rootkey-toolkit v" + RootKeyConstants.TOOL_VERSION
                + " — 根密钥管理工具（4-of-4 分片 / AES-256-GCM）");
        ps.println();
        ps.println("用法:");
        ps.println("  rootkey generate --out <目录> [--key-id <名称>] [--force]");
        ps.println("        生成根密钥的四个组件 a/b/c/d（本地操作，生成后分发给服务器）");
        ps.println("  rootkey verify <组件目录 | a b c d 四个文件> [--config <配置文件>]");
        ps.println("        校验组件完整性、一致性并试还原");
        ps.println("  rootkey restore <组件目录 | a b c d 四个文件> [--config <配置文件>]");
        ps.println("        还原根密钥（仅显示 KCV，绝不输出密钥本体）");
        ps.println("  rootkey encrypt <组件目录 | a b c d 四个文件> [--config <配置文件>]");
        ps.println("                   [--in <文件|->] [--out <文件|->] [--base64]");
        ps.println("  rootkey decrypt <同 encrypt>");
        ps.println("  rootkey ui [--port 8765]");
        ps.println("        启动本地 Web 管理台（仅监听 127.0.0.1）：生成/校验/还原/加解密");
        ps.println("  rootkey client");
        ps.println("        打开桌面客户端窗口（Swing 图形界面，内部直接调用 SDK）");
        ps.println("  rootkey workkey gen --name <名称> [--out <文件>] [--force] <根密钥组件>");
        ps.println("        生成工作密钥并用根密钥加密写入 .json 文件（信封加密）");
        ps.println("        同一文件可存多个工作密钥：文件已存在时为追加，同名条目需 --force 覆盖");
        ps.println("  rootkey workkey restore --workkey <文件> [--name <名称>] <根密钥组件>");
        ps.println("        用根密钥还原工作密钥并自校验（只显示 KCV；文件内仅一个密钥时可省略 --name）");
        ps.println("  rootkey workkey encrypt/decrypt --workkey <文件> [--name <名称>] <根密钥组件>");
        ps.println("        用工作密钥加解密（AES-256-GCM，选项同根密钥加解密）");
        ps.println("  rootkey workkey list --workkey <文件>");
        ps.println("        列出文件内全部工作密钥（名称/KCV，无需根密钥）");
        ps.println();
        ps.println("选项:");
        ps.println("  --in      输入文件，\"-\" 或省略表示标准输入");
        ps.println("  --out     输出文件，\"-\" 或省略表示标准输出");
        ps.println("  --base64  密文用 Base64 编码（文本友好；解密时同样先按 Base64 解码）");
        ps.println("  --config  从配置文件读取组件位置（rootkey.component.a.path 等 4 项）");
        ps.println();
        ps.println("示例:");
        ps.println("  rootkey generate --out ./secrets --key-id order-service");
        ps.println("  rootkey verify ./secrets");
        ps.println("  echo -n '机密数据' | rootkey encrypt ./secrets --base64");
        ps.println("  rootkey decrypt ./secrets --in msg.b64 --base64");
    }

    private static final class UsageException extends RuntimeException {
        private static final long serialVersionUID = 1L;

        UsageException(String message) {
            super(message);
        }
    }
}
