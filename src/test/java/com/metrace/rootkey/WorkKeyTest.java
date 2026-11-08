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
 * 工作密钥（信封加密）测试：生成 → 落盘 → 还原 → 业务加解密 → 异常场景。
 */
class WorkKeyTest {

    private static RootKeyManager rootFor(Path dir) {
        RootKeyConfig cfg = RootKeyConfig.builder()
                .a(dir.resolve("a.comp")).b(dir.resolve("b.comp"))
                .c(dir.resolve("c.comp")).d(dir.resolve("d.comp")).build();
        return new RootKeyManager(cfg);
    }

    @Test
    void generateThenRestoreRoundTrip(@TempDir Path dir) throws Exception {
        try (RootKeyGenerator.GenerateResult ignored = RootKeyGenerator.generate(dir, "app-root", false)) {
            Path wkFile = dir.resolve("mydb.workkey");
            byte[] generatedKey;
            String generatedKcv;
            try (RootKeyManager root = rootFor(dir);
                 WorkKeyManager.Generated g =
                         WorkKeyManager.generate(wkFile, "mydb-key", root, false)) {
                assertEquals("mydb-key", g.name());
                assertEquals(16, g.kcvHex().length());
                assertTrue(Files.exists(wkFile));
                generatedKey = g.secret().exportKey();
                generatedKcv = g.kcvHex();
            }
            // 文件里没有明文密钥：wrapped 区域不包含 32 字节明文
            String fileText = new String(Files.readAllBytes(wkFile), StandardCharsets.UTF_8);
            assertFalse(fileText.contains("material="), "工作密钥文件不应包含根密钥组件字段");
            assertTrue(fileText.contains("name=mydb-key"));
            assertTrue(fileText.contains("rootKeyId=app-root"));

            // 业务侧：根密钥 + workkey 文件路径 → 还原到内存
            try (RootKeyManager root = rootFor(dir);
                 WorkKeyManager wk = new WorkKeyManager(root, wkFile)) {
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
    void restoreIsStableAcrossInstances(@TempDir Path dir) throws Exception {
        try (RootKeyGenerator.GenerateResult ignored = RootKeyGenerator.generate(dir, "stable-root", false)) {
            Path wkFile = dir.resolve("svc.workkey");
            final byte[] expected;
            try (RootKeyManager root = rootFor(dir);
                 WorkKeyManager.Generated g = WorkKeyManager.generate(wkFile, "svc-key", root, false)) {
                expected = g.secret().exportKey();
            }
            // 多次、多实例还原：结果必须一致（稳定性）
            for (int i = 0; i < 5; i++) {
                try (RootKeyManager root = rootFor(dir);
                     WorkKeyManager wk = new WorkKeyManager(root, wkFile)) {
                    try (WorkKeySecret s = WorkKeyManager.restore(wkFile, root)) {
                        assertArrayEquals(expected, s.exportKey(), "第 " + i + " 次还原不一致");
                    }
                }
            }
        }
    }

    @Test
    void wrongRootKeyRejected(@TempDir Path dir) throws Exception {
        Path other = dir.resolve("other");
        try (RootKeyGenerator.GenerateResult ignored = RootKeyGenerator.generate(dir, "right-root", false)) {
            RootKeyGenerator.generate(other, "wrong-root", false).close();
            Path wkFile = dir.resolve("k.workkey");
            try (RootKeyManager root = rootFor(dir);
                 WorkKeyManager.Generated ignored2 = WorkKeyManager.generate(wkFile, "k-one", root, false)) {
                // 用另一把根密钥还原 → 归属核对失败
                try (RootKeyManager wrong = rootFor(other)) {
                    RootKeyException ex = assertThrows(RootKeyException.class,
                            () -> WorkKeyManager.restore(wkFile, wrong));
                    assertTrue(ex.getMessage().contains("根密钥不匹配"), ex.getMessage());
                }
            }
        }
    }

    @Test
    void tamperedWorkKeyFileRejected(@TempDir Path dir) throws Exception {
        try (RootKeyGenerator.GenerateResult ignored = RootKeyGenerator.generate(dir, "tamper-root", false)) {
            Path wkFile = dir.resolve("t.workkey");
            try (RootKeyManager root = rootFor(dir);
                 WorkKeyManager.Generated ignored2 = WorkKeyManager.generate(wkFile, "t-key", root, false)) {
                String content = new String(Files.readAllBytes(wkFile), StandardCharsets.UTF_8);
                String tampered = content.replaceAll("(?m)^name=(.{3})", "name=XXX");
                Files.write(wkFile, tampered.getBytes(StandardCharsets.UTF_8));
                assertThrows(RootKeyException.class, () -> WorkKeyFile.load(wkFile));
            }
        }
    }

    @Test
    void invalidNameRejected(@TempDir Path dir) throws Exception {
        try (RootKeyGenerator.GenerateResult ignored = RootKeyGenerator.generate(dir, "name-root", false)) {
            try (RootKeyManager root = rootFor(dir)) {
                assertThrows(RootKeyException.class,
                        () -> WorkKeyManager.generate(dir.resolve("bad1.workkey"), "../evil", root, false));
                assertThrows(RootKeyException.class,
                        () -> WorkKeyManager.generate(dir.resolve("bad2.workkey"), "", root, false));
            }
        }
    }

    @Test
    void overwriteRequiresForce(@TempDir Path dir) throws Exception {
        try (RootKeyGenerator.GenerateResult ignored = RootKeyGenerator.generate(dir, "force-root", false)) {
            Path wkFile = dir.resolve("f.workkey");
            try (RootKeyManager root = rootFor(dir)) {
                WorkKeyManager.generate(wkFile, "f-key", root, false).close();
                assertThrows(RootKeyException.class,
                        () -> WorkKeyManager.generate(wkFile, "f-key", root, false));
                // force 覆盖后仍可正常还原
                WorkKeyManager.generate(wkFile, "f-key", root, true).close();
                try (WorkKeySecret s = WorkKeyManager.restore(wkFile, root)) {
                    assertEquals("f-key", s.name());
                }
            }
        }
    }
}
