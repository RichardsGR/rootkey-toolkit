package com.metrace.rootkey.webui;

import com.metrace.rootkey.RootKeyConstants;
import com.metrace.rootkey.RootKeyException;
import com.metrace.rootkey.RootKeyManager;
import com.metrace.rootkey.config.RootKeyConfig;
import com.metrace.rootkey.core.ComponentFile;
import com.metrace.rootkey.core.RootKeyGenerator;
import com.metrace.rootkey.core.RootKeyRestorer;
import com.metrace.rootkey.core.RootKeySecret;
import com.metrace.rootkey.internal.Codec;
import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpServer;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.ThreadFactory;
import java.util.concurrent.atomic.AtomicInteger;

/**
 * 本地 Web 管理页面服务（纯 JDK HttpServer，零依赖）。
 *
 * <p>安全边界：</p>
 * <ul>
 *   <li>只绑定 127.0.0.1，外部主机无法访问</li>
 *   <li>所有 /api 接口要求 Content-Type: application/json——浏览器无法跨站伪造该类型
 *       （会触发 CORS 预检，而本服务不返回任何 CORS 头），天然防 CSRF</li>
 *   <li>任何接口都不输出根密钥本体，只输出 KCV 指纹</li>
 * </ul>
 *
 * <p>API（全部 POST /api/*，请求与响应均为 UTF-8 JSON）：</p>
 * <pre>
 *   /api/generate {outDir, keyId?, force?}        → {keyId, kcv, components:[...], manifest}
 *   /api/verify   {dir} 或 {a,b,c,d}              → {keyId, kcv, files:[{path,label,ok?,error?}]}
 *   /api/encrypt  {dir|a,b,c,d, plaintext}        → {keyId, kcv, ciphertextB64}
 *   /api/decrypt  {dir|a,b,c,d, ciphertextB64}    → {keyId, kcv, plaintext}
 *   /api/info     GET                             → {version}
 * </pre>
 */
public final class WebUiServer {

    private final HttpServer server;

    public WebUiServer(int port) throws IOException {
        server = HttpServer.create(new InetSocketAddress("127.0.0.1", port), 0);
        server.createContext("/", this::handleIndex);
        server.createContext("/api/info", this::handleInfo);
        server.createContext("/api/generate", guarded(this::handleGenerate));
        server.createContext("/api/verify", guarded(this::handleVerify));
        server.createContext("/api/encrypt", guarded(this::handleEncryptDecrypt));
        server.createContext("/api/decrypt", guarded(this::handleEncryptDecrypt));
        server.setExecutor(newDaemonPool());
    }

    /** 启动服务（非阻塞） */
    public void start() {
        server.start();
    }

    public void stop() {
        server.stop(0);
    }

    /** 实际监听端口（构造时传 0 可由系统分配） */
    public int port() {
        return server.getAddress().getPort();
    }

    // ------------------------------------------------------------------ handlers

    private void handleIndex(HttpExchange ex) throws IOException {
        if (!"GET".equals(ex.getRequestMethod())) {
            sendJson(ex, 405, "{\"ok\":false,\"error\":\"仅支持 GET\"}");
            return;
        }
        byte[] page = loadPage();
        ex.getResponseHeaders().set("Content-Type", "text/html; charset=utf-8");
        ex.getResponseHeaders().set("X-Content-Type-Options", "nosniff");
        ex.sendResponseHeaders(200, page.length);
        OutputStream os = ex.getResponseBody();
        os.write(page);
        os.close();
    }

    private void handleInfo(HttpExchange ex) throws IOException {
        sendJson(ex, 200, "{\"ok\":true,\"version\":\"" + RootKeyConstants.TOOL_VERSION + "\"}");
    }

    private void handleGenerate(HttpExchange ex, Map<String, String> p) throws IOException {
        String outDir = p.get("outDir");
        if (outDir == null || outDir.trim().isEmpty()) {
            throw new RootKeyException("缺少参数 outDir（组件输出目录）");
        }
        Path dir = Paths.get(outDir.trim()).toAbsolutePath().normalize();
        boolean force = "true".equals(p.get("force"));
        try (RootKeyGenerator.GenerateResult r =
                     RootKeyManager.generate(dir, p.get("keyId"), force)) {
            StringBuilder comps = new StringBuilder();
            char[] labels = RootKeyConstants.COMPONENT_LABELS;
            List<Path> paths = r.componentPaths();
            for (int i = 0; i < paths.size(); i++) {
                if (i > 0) {
                    comps.append(',');
                }
                comps.append("{\"label\":\"").append(labels[i])
                        .append("\",\"path\":\"").append(Json.escape(paths.get(i).toString()))
                        .append("\",\"bytes\":").append(Files.size(paths.get(i)))
                        .append('}');
            }
            sendJson(ex, 200, "{\"ok\":true,\"keyId\":\"" + Json.escape(r.keyId())
                    + "\",\"kcv\":\"" + r.kcvHex()
                    + "\",\"manifest\":\"" + Json.escape(r.manifestPath().toString())
                    + "\",\"components\":[" + comps + "]}");
        }
    }

    private void handleVerify(HttpExchange ex, Map<String, String> p) throws IOException {
        List<Path> paths = componentPaths(p);
        StringBuilder files = new StringBuilder();
        List<ComponentFile> comps = new ArrayList<ComponentFile>();
        boolean allOk = true;
        for (int i = 0; i < paths.size(); i++) {
            Path path = paths.get(i);
            char label = RootKeyConstants.COMPONENT_LABELS[i];
            String entry;
            try {
                if (!Files.isReadable(path)) {
                    throw new RootKeyException("文件不存在或不可读");
                }
                ComponentFile cf = ComponentFile.load(path);
                comps.add(cf);
                entry = "{\"label\":\"" + label
                        + "\",\"path\":\"" + Json.escape(path.toString())
                        + "\",\"keyId\":\"" + Json.escape(cf.keyId())
                        + "\",\"ok\":true}";
            } catch (RuntimeException e) {
                allOk = false;
                entry = "{\"label\":\"" + label
                        + "\",\"path\":\"" + Json.escape(path.toString())
                        + "\",\"ok\":false,\"error\":\"" + Json.escape(e.getMessage()) + "\"}";
            }
            if (i > 0) {
                files.append(',');
            }
            files.append(entry);
        }
        if (allOk && comps.size() == 4) {
            try (RootKeySecret secret = RootKeyRestorer.restoreFiles(comps)) {
                sendJson(ex, 200, "{\"ok\":true,\"keyId\":\"" + Json.escape(secret.keyId())
                        + "\",\"kcv\":\"" + secret.kcvHex()
                        + "\",\"files\":[" + files + "]}");
                return;
            } catch (RuntimeException e) {
                allOk = false;
                files.append(",{\"ok\":false,\"error\":\"").append(Json.escape(e.getMessage())).append("\"}");
            }
        }
        sendJson(ex, 200, "{\"ok\":false,\"files\":[" + files + "]}");
    }

    private void handleEncryptDecrypt(HttpExchange ex, Map<String, String> p) throws IOException {
        String uri = ex.getRequestURI().getPath();
        boolean isEncrypt = uri.endsWith("/encrypt");
        RootKeyConfig cfg = configFrom(p);
        try (RootKeyManager km = new RootKeyManager(cfg)) {
            if (isEncrypt) {
                String plaintext = p.get("plaintext");
                if (plaintext == null) {
                    throw new RootKeyException("缺少参数 plaintext");
                }
                sendJson(ex, 200, "{\"ok\":true,\"keyId\":\"" + Json.escape(km.keyId())
                        + "\",\"kcv\":\"" + km.kcv()
                        + "\",\"ciphertextB64\":\"" + km.encryptToBase64(plaintext) + "\"}");
            } else {
                String ciphertextB64 = p.get("ciphertextB64");
                if (ciphertextB64 == null || ciphertextB64.trim().isEmpty()) {
                    throw new RootKeyException("缺少参数 ciphertextB64");
                }
                sendJson(ex, 200, "{\"ok\":true,\"keyId\":\"" + Json.escape(km.keyId())
                        + "\",\"kcv\":\"" + km.kcv()
                        + "\",\"plaintext\":\"" + Json.escape(km.decryptFromBase64(ciphertextB64)) + "\"}");
            }
        }
    }

    // ------------------------------------------------------------------ helpers

    /** 接口统一包装：JSON 内容类型校验（防 CSRF）+ 统一异常 → JSON */
    private com.sun.net.httpserver.HttpHandler guarded(final ApiHandler inner) {
        return new com.sun.net.httpserver.HttpHandler() {
            @Override
            public void handle(HttpExchange ex) throws IOException {
                if (!"POST".equals(ex.getRequestMethod())) {
                    sendJson(ex, 405, "{\"ok\":false,\"error\":\"仅支持 POST\"}");
                    return;
                }
                String ct = ex.getRequestHeaders().getFirst("Content-Type");
                if (ct == null || !ct.toLowerCase().contains("application/json")) {
                    sendJson(ex, 403, "{\"ok\":false,\"error\":\"Content-Type 必须为 application/json\"}");
                    return;
                }
                try {
                    String body = new String(Codec.readAll(ex.getRequestBody()), StandardCharsets.UTF_8);
                    Map<String, String> params = body.trim().isEmpty()
                            ? java.util.Collections.<String, String>emptyMap()
                            : Json.parseFlatObject(body);
                    inner.handle(ex, params);
                } catch (RuntimeException e) {
                    sendJson(ex, 200, "{\"ok\":false,\"error\":\""
                            + Json.escape(e.getMessage() == null ? e.toString() : e.getMessage()) + "\"}");
                }
            }
        };
    }

    private interface ApiHandler {
        void handle(HttpExchange ex, Map<String, String> params) throws IOException;
    }

    /** 解析组件位置：{dir} → dir/{a,b,c,d}.comp；或显式 {a,b,c,d} 四个路径（不做存在性检查） */
    private static List<Path> componentPaths(Map<String, String> p) {
        List<Path> paths = new ArrayList<Path>();
        String dir = p.get("dir");
        if (dir != null && !dir.trim().isEmpty()) {
            Path d = Paths.get(dir.trim());
            for (char label : RootKeyConstants.COMPONENT_LABELS) {
                paths.add(d.resolve(label + RootKeyConstants.COMPONENT_FILE_SUFFIX));
            }
        } else {
            for (char label : RootKeyConstants.COMPONENT_LABELS) {
                String v = p.get(String.valueOf(label));
                if (v == null || v.trim().isEmpty()) {
                    throw new RootKeyException("缺少参数 dir 或四个组件路径 a/b/c/d");
                }
                paths.add(Paths.get(v.trim()));
            }
        }
        return paths;
    }

    private static RootKeyConfig configFrom(Map<String, String> p) {
        List<Path> paths = componentPaths(p);
        List<String> missing = new ArrayList<String>();
        for (Path path : paths) {
            if (!Files.isReadable(path)) {
                missing.add(path.toString());
            }
        }
        if (!missing.isEmpty()) {
            throw new RootKeyException("组件文件不存在或不可读: " + String.join(", ", missing));
        }
        return RootKeyConfig.builder()
                .a(paths.get(0)).b(paths.get(1)).c(paths.get(2)).d(paths.get(3)).build();
    }

    private static void sendJson(HttpExchange ex, int status, String json) throws IOException {
        byte[] body = json.getBytes(StandardCharsets.UTF_8);
        ex.getResponseHeaders().set("Content-Type", "application/json; charset=utf-8");
        ex.getResponseHeaders().set("X-Content-Type-Options", "nosniff");
        ex.sendResponseHeaders(status, body.length);
        OutputStream os = ex.getResponseBody();
        os.write(body);
        os.close();
    }

    private byte[] loadPage() throws IOException {
        InputStream in = WebUiServer.class.getResourceAsStream("/web/index.html");
        if (in == null) {
            throw new IOException("未找到内置页面资源 /web/index.html");
        }
        try {
            return Codec.readAll(in);
        } finally {
            in.close();
        }
    }

    private static ExecutorService newDaemonPool() {
        ThreadFactory parent = Executors.defaultThreadFactory();
        final AtomicInteger seq = new AtomicInteger();
        return Executors.newFixedThreadPool(4, new ThreadFactory() {
            @Override
            public Thread newThread(Runnable r) {
                Thread t = parent.newThread(r);
                t.setName("rootkey-ui-" + seq.incrementAndGet());
                t.setDaemon(true);
                return t;
            }
        });
    }
}
