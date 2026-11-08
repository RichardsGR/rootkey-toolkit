package com.metrace.rootkey;

import com.metrace.rootkey.webui.Json;
import com.metrace.rootkey.webui.WebUiServer;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.io.InputStream;
import java.io.OutputStream;
import java.net.HttpURLConnection;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Web 管理台 API 集成测试：起真实服务（随机端口），走 HTTP 全链路。
 */
class WebUiServerTest {

    @Test
    void fullRoundTripThroughHttp(@TempDir Path dir) throws Exception {
        WebUiServer server = new WebUiServer(0);
        server.start();
        try {
            int port = server.port();
            String base = "http://127.0.0.1:" + port;

            // 生成
            Map<String, String> gen = Json.parseFlatObject(post(base + "/api/generate",
                    "{\"outDir\":\"" + jsonEscape(dir.toString()) + "\",\"keyId\":\"web-test\"}"));
            assertTrue(Boolean.parseBoolean(gen.get("ok")), "generate 应成功: " + gen.get("error"));
            assertEquals("web-test", gen.get("keyId"));
            assertEquals(16, gen.get("kcv").length());
            assertTrue(Files.exists(dir.resolve("a.comp")));

            // 校验
            Map<String, String> verify = Json.parseFlatObject(post(base + "/api/verify",
                    "{\"dir\":\"" + jsonEscape(dir.toString()) + "\"}"));
            assertTrue(Boolean.parseBoolean(verify.get("ok")), "verify 应成功: " + verify.get("error"));
            assertEquals(gen.get("kcv"), verify.get("kcv"));

            // 加密
            Map<String, String> enc = Json.parseFlatObject(post(base + "/api/encrypt",
                    "{\"dir\":\"" + jsonEscape(dir.toString()) + "\",\"plaintext\":\"网页加密测试\"}"));
            assertTrue(Boolean.parseBoolean(enc.get("ok")), "encrypt 应成功: " + enc.get("error"));
            assertNotNull(enc.get("ciphertextB64"));

            // 解密
            Map<String, String> dec = Json.parseFlatObject(post(base + "/api/decrypt",
                    "{\"dir\":\"" + jsonEscape(dir.toString()) + "\",\"ciphertextB64\":\""
                            + enc.get("ciphertextB64") + "\"}"));
            assertTrue(Boolean.parseBoolean(dec.get("ok")), "decrypt 应成功: " + dec.get("error"));
            assertEquals("网页加密测试", dec.get("plaintext"));
        } finally {
            server.stop();
        }
    }

    @Test
    void rejectsNonJsonContentType(@TempDir Path dir) throws Exception {
        WebUiServer server = new WebUiServer(0);
        server.start();
        try {
            // 表单类型请求必须被拒（防 CSRF：浏览器可跨站发表单，但发不了 application/json）
            HttpURLConnection conn = (HttpURLConnection)
                    new URL("http://127.0.0.1:" + server.port() + "/api/encrypt").openConnection();
            conn.setRequestMethod("POST");
            conn.setRequestProperty("Content-Type", "application/x-www-form-urlencoded");
            conn.setDoOutput(true);
            conn.getOutputStream().write("dir=x&plaintext=y".getBytes(StandardCharsets.UTF_8));
            assertEquals(403, conn.getResponseCode());
        } finally {
            server.stop();
        }
    }

    @Test
    void verifyReportsBadComponentsGracefully(@TempDir Path dir) throws Exception {
        WebUiServer server = new WebUiServer(0);
        server.start();
        try {
            Map<String, String> r = Json.parseFlatObject(post(
                    "http://127.0.0.1:" + server.port() + "/api/verify",
                    "{\"dir\":\"" + jsonEscape(dir.toString()) + "\"}"));
            assertFalse(Boolean.parseBoolean(r.get("ok")), "空目录校验应失败");
            assertNotNull(r.get("files"), "应返回逐文件明细");
        } finally {
            server.stop();
        }
    }

    @Test
    void indexPageServed() throws Exception {
        WebUiServer server = new WebUiServer(0);
        server.start();
        try {
            HttpURLConnection conn = (HttpURLConnection)
                    new URL("http://127.0.0.1:" + server.port() + "/").openConnection();
            assertEquals(200, conn.getResponseCode());
            assertEquals("text/html; charset=utf-8", conn.getHeaderField("Content-Type"));
            String html = readAll(conn.getInputStream());
            assertTrue(html.contains("RootKey 管理台"));
            assertTrue(html.contains("api/generate"));
        } finally {
            server.stop();
        }
    }

    // ------------------------------------------------------------------ helpers

    /** POST JSON 并以 Map 返回响应（HTTP 层错误直接抛） */
    private static String post(String url, String json) throws Exception {
        HttpURLConnection conn = (HttpURLConnection) new URL(url).openConnection();
        conn.setRequestMethod("POST");
        conn.setRequestProperty("Content-Type", "application/json");
        conn.setDoOutput(true);
        OutputStream os = conn.getOutputStream();
        os.write(json.getBytes(StandardCharsets.UTF_8));
        os.close();
        InputStream in = conn.getResponseCode() < 400
                ? conn.getInputStream() : conn.getErrorStream();
        return readAll(in);
    }

    private static String readAll(InputStream in) throws Exception {
        java.io.ByteArrayOutputStream bos = new java.io.ByteArrayOutputStream();
        byte[] buf = new byte[8192];
        int n;
        while ((n = in.read(buf)) > 0) {
            bos.write(buf, 0, n);
        }
        in.close();
        return new String(bos.toByteArray(), StandardCharsets.UTF_8);
    }

    /** 路径塞进 JSON 字符串时转义反斜杠/引号 */
    private static String jsonEscape(String s) {
        return s.replace("\\", "\\\\").replace("\"", "\\\"");
    }
}
