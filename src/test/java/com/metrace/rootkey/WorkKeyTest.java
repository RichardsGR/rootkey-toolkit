package com.metrace.rootkey;

import com.metrace.rootkey.config.RootKeyConfig;
import com.metrace.rootkey.core.RootKeyGenerator;
import com.metrace.rootkey.workkey.WorkKeyFile;
import com.metrace.rootkey.workkey.WorkKeyManager;
import com.metrace.rootkey.workkey.WorkKeySecret;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;

import static org.junit.jupiter.api.Assertions.*;

/**
 * 工作密钥（信封加密）测试：生成 → JSON 落盘（多密钥容器）→ 按名还原 → 业务加解密 → 异常场景。
 */
class WorkKeyTest {

    private static RootKeyManager rootFor(Path dir) {
        RootKeyConfig cfg = RootKeyConfig.builder()
                .a(dir.resolve("a.txt")).b(dir.resolve("b.txt"))
                .c(dir.resolve("c.txt")).d(dir.resolve("d.txt")).build();
        return new RootKeyManager(cfg);
    }

    @Test
    void generateThenRestoreRoundTrip(@TempDir Path dir) throws Exception {
        try (RootKeyGenerator.GenerateResult ignored = RootKeyGenerator.generate(dir, "app-root", false)) {
            Path wkFile = dir.resolve("mydb.json");
            byte[] generatedKey;
            String generatedKcv;
            try (RootKeyManager root = rootFor(dir);
                 WorkKeyManager.Generated g =
                         WorkKeyManager.generate(wkFile, "mydb-key", root, false)) {
                assertEquals("mydb-key", g.name());
                assertEquals(16, g.kcvHex().length());
                assertTrue(Files.exists(wkFile));
                assertEquals(1, g.namesInFile().size());
                generatedKey = g.secret().exportKey();
                generatedKcv = g.kcvHex();
            }
            // JSON 文件结构：只有密文材料，不含根密钥组件
            String fileText = new String(Files.readAllBytes(wkFile), StandardCharsets.UTF_8);
            assertFalse(fileText.contains("material="), "工作密钥文件不应包含根密钥组件字段");
            assertTrue(fileText.contains("\"name\": \"mydb-key\""));
            assertTrue(fileText.contains("\"rootKeyId\": \"app-root\""));

            // 业务侧：根密钥 + workkey 文件路径 + 名称 → 还原到内存
            try (RootKeyManager root = rootFor(dir);
                 WorkKeyManager wk = new WorkKeyManager(root, wkFile, "mydb-key")) {
                assertEquals("mydb-key", wk.name());
                assertEquals(generatedKcv, wk.kcv());
                assertArrayEquals(generatedKey, wk.secret().exportKey());
                // AES-256 业务加解密
                String secret = "业务数据-工作密钥加密 🤫";
                assertEquals(secret, wk.decryptFromBase64(wk.encryptToBase64(secret)));
                byte[] blob = new byte[2048];
                new java.util.Random(7).nextBytes(blob);
                assertArrayEquals(blob, wk.decrypt(wk.encrypt(blob)));
            }
        }
    }

    @Test
    void multipleKeysInOneFile(@TempDir Path dir) throws Exception {
        try (RootKeyGenerator.GenerateResult ignored = RootKeyGenerator.generate(dir, "multi-root", false)) {
            Path wkFile = dir.resolve("keys.json");
            byte[] keyA, keyB;
            try (RootKeyManager root = rootFor(dir)) {
                try (WorkKeyManager.Generated g = WorkKeyManager.generate(wkFile, "key-a", root, false)) {
                    keyA = g.secret().exportKey();
                }
                // 同一文件再次生成 → 追加
                try (WorkKeyManager.Generated g = WorkKeyManager.generate(wkFile, "key-b", root, false)) {
                    keyB = g.secret().exportKey();
                    assertEquals(2, g.namesInFile().size());
                    assertEquals("[key-a, key-b]", g.namesInFile().toString());
                }
                assertFalse(java.util.Arrays.equals(keyA, keyB), "两个工作密钥应各自随机");
            }
            // 按名还原：各自拿到正确的密钥
            try (RootKeyManager root = rootFor(dir);
                 WorkKeySecret sa = WorkKeyManager.restore(wkFile, "key-a", root);
                 WorkKeySecret sb = WorkKeyManager.restore(wkFile, "key-b", root)) {
                assertArrayEquals(keyA, sa.exportKey());
                assertArrayEquals(keyB, sb.exportKey());
            }
            // 直读文件（无需根密钥）
            WorkKeyFile f = WorkKeyFile.load(wkFile);
            assertEquals(2, f.keyCount());
            assertEquals("key-a", f.names().get(0));
            // 不传名称且文件内有多个密钥 → 报错并附名称列表
            try (RootKeyManager root = rootFor(dir)) {
                RootKeyException ex = assertThrows(RootKeyException.class,
                        () -> WorkKeyManager.restore(wkFile, null, root));
                assertTrue(ex.getMessage().contains("key-a") && ex.getMessage().contains("key-b"),
                        "报错应列出文件内密钥名称: " + ex.getMessage());
            }
        }
    }

    @Test
    void duplicateNameRequiresForce(@TempDir Path dir) throws Exception {
        try (RootKeyGenerator.GenerateResult ignored = RootKeyGenerator.generate(dir, "dup-root", false)) {
            Path wkFile = dir.resolve("dup.json");
            try (RootKeyManager root = rootFor(dir)) {
                WorkKeyManager.generate(wkFile, "svc", root, false).close();
                // 同名追加被拒
                RootKeyException ex = assertThrows(RootKeyException.class,
                        () -> WorkKeyManager.generate(wkFile, "svc", root, false));
                assertTrue(ex.getMessage().contains("同名"), ex.getMessage());
                // force → 覆盖同一条目，文件仍只有 1 个密钥
                try (WorkKeyManager.Generated g = WorkKeyManager.generate(wkFile, "svc", root, true)) {
                    assertEquals(1, g.namesInFile().size());
                }
                try (WorkKeySecret s = WorkKeyManager.restore(wkFile, "svc", root)) {
                    assertEquals("svc", s.name());
                }
            }
        }
    }

    @Test
    void restoreIsStableAcrossInstances(@TempDir Path dir) throws Exception {
        try (RootKeyGenerator.GenerateResult ignored = RootKeyGenerator.generate(dir, "stable-root", false)) {
            Path wkFile = dir.resolve("svc.json");
            final byte[] expected;
            try (RootKeyManager root = rootFor(dir);
                 WorkKeyManager.Generated g = WorkKeyManager.generate(wkFile, "svc-key", root, false)) {
                expected = g.secret().exportKey();
            }
            for (int i = 0; i < 5; i++) {
                try (RootKeyManager root = rootFor(dir);
                     WorkKeySecret s = WorkKeyManager.restore(wkFile, "svc-key", root)) {
                    assertArrayEquals(expected, s.exportKey(), "第 " + i + " 次还原不一致");
                }
            }
        }
    }

    @Test
    void wrongRootKeyRejected(@TempDir Path dir) throws Exception {
        Path other = dir.resolve("other");
        try (RootKeyGenerator.GenerateResult ignored = RootKeyGenerator.generate(dir, "right-root", false)) {
            RootKeyGenerator.generate(other, "wrong-root", false).close();
            Path wkFile = dir.resolve("k.json");
            try (RootKeyManager root = rootFor(dir);
                 WorkKeyManager.Generated ignored2 = WorkKeyManager.generate(wkFile, "k-one", root, false)) {
                try (RootKeyManager wrong = rootFor(other)) {
                    RootKeyException ex = assertThrows(RootKeyException.class,
                            () -> WorkKeyManager.restore(wkFile, "k-one", wrong));
                    assertTrue(ex.getMessage().contains("根密钥不匹配"), ex.getMessage());
                }
            }
        }
    }

    @Test
    void appendWithDifferentRootRejected(@TempDir Path dir) throws Exception {
        Path other = dir.resolve("other");
        try (RootKeyGenerator.GenerateResult ignored = RootKeyGenerator.generate(dir, "root-x", false)) {
            RootKeyGenerator.generate(other, "root-y", false).close();
            Path wkFile = dir.resolve("mix.json");
            try (RootKeyManager rootX = rootFor(dir)) {
                WorkKeyManager.generate(wkFile, "kx", rootX, false).close();
            }
            // 另一把根密钥往同一文件追加 → 必须被拒（防止混密）
            try (RootKeyManager rootY = rootFor(other)) {
                RootKeyException ex = assertThrows(RootKeyException.class,
                        () -> WorkKeyManager.generate(wkFile, "ky", rootY, false));
                assertTrue(ex.getMessage().contains("不一致"), ex.getMessage());
            }
        }
    }

    @Test
    void tamperedWorkKeyFileRejected(@TempDir Path dir) throws Exception {
        try (RootKeyGenerator.GenerateResult ignored = RootKeyGenerator.generate(dir, "tamper-root", false)) {
            Path wkFile = dir.resolve("t.json");
            try (RootKeyManager root = rootFor(dir);
                 WorkKeyManager.Generated ignored2 = WorkKeyManager.generate(wkFile, "t-key", root, false)) {
                String content = new String(Files.readAllBytes(wkFile), StandardCharsets.UTF_8);
                // 篡改 wrapped 的开头 4 个字符（保留引号与 JSON 结构）
                String tampered = content.replaceFirst("(\"wrapped\": \")....", "$1XXXX");
                assertNotEquals(content, tampered, "篡改应实际发生");
                Files.write(wkFile, tampered.getBytes(StandardCharsets.UTF_8));
                RootKeyException ex = assertThrows(RootKeyException.class,
                        () -> WorkKeyFile.load(wkFile));
                assertTrue(ex.getMessage().contains("校验和不匹配"), ex.getMessage());
            }
        }
    }

    @Test
    void invalidNameRejected(@TempDir Path dir) throws Exception {
        try (RootKeyGenerator.GenerateResult ignored = RootKeyGenerator.generate(dir, "name-root", false)) {
            try (RootKeyManager root = rootFor(dir)) {
                assertThrows(RootKeyException.class,
                        () -> WorkKeyManager.generate(dir.resolve("bad1.json"), "../evil", root, false));
                assertThrows(RootKeyException.class,
                        () -> WorkKeyManager.generate(dir.resolve("bad2.json"), "", root, false));
            }
        }
    }
}
