package com.metrace.rootkey;

import com.metrace.rootkey.config.RootKeyConfig;
import com.metrace.rootkey.core.ComponentFile;
import com.metrace.rootkey.core.RootKeyGenerator;
import com.metrace.rootkey.core.RootKeyRestorer;
import com.metrace.rootkey.core.RootKeySecret;
import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Properties;

import static org.junit.jupiter.api.Assertions.*;

/**
 * 核心链路测试：生成 → 还原 → 加解密 → 各种异常场景。
 */
class CoreRoundTripTest {

    @Test
    void generateCreatesFourComponentsAndManifest(@org.junit.jupiter.api.io.TempDir Path dir) throws Exception {
        try (RootKeyGenerator.GenerateResult r = RootKeyGenerator.generate(dir, "test-key-1", false)) {
            List<Path> paths = r.componentPaths();
            assertEquals(4, paths.size());
            for (Path p : paths) {
                assertTrue(Files.exists(p), "组件文件应存在: " + p);
            }
            assertTrue(Files.exists(r.manifestPath()));
            // 四份材料互不相同
            List<byte[]> mats = new ArrayList<byte[]>();
            for (Path p : paths) {
                mats.add(ComponentFile.load(p).material());
            }
            for (int i = 0; i < mats.size(); i++) {
                for (int j = i + 1; j < mats.size(); j++) {
                    assertFalse(Arrays.equals(mats.get(i), mats.get(j)), "组件材料不应重复");
                }
            }
        }
    }

    @Test
    void restoreIsDeterministicAndMatchesGenerationKcv(@org.junit.jupiter.api.io.TempDir Path dir) throws Exception {
        String expectedKcv;
        byte[] expectedKey;
        try (RootKeyGenerator.GenerateResult r = RootKeyGenerator.generate(dir, "det-key", false)) {
            expectedKcv = r.kcvHex();
            expectedKey = r.secret().exportKey();
        }
        // 连续还原 3 次，结果完全一致
        for (int i = 0; i < 3; i++) {
            RootKeySecret s = RootKeyRestorer.restore(
                    dir.resolve("a.comp"), dir.resolve("b.comp"),
                    dir.resolve("c.comp"), dir.resolve("d.comp"));
            assertEquals(expectedKcv, s.kcvHex());
            assertArrayEquals(expectedKey, s.exportKey());
            s.destroy();
        }
    }

    @Test
    void encryptDecryptRoundTripBinaryAndText(@org.junit.jupiter.api.io.TempDir Path dir) throws Exception {
        Properties props = new Properties();
        props.setProperty(RootKeyConfig.KEY_A, dir.resolve("a.comp").toString());
        props.setProperty(RootKeyConfig.KEY_B, dir.resolve("b.comp").toString());
        props.setProperty(RootKeyConfig.KEY_C, dir.resolve("c.comp").toString());
        props.setProperty(RootKeyConfig.KEY_D, dir.resolve("d.comp").toString());
        try (RootKeyGenerator.GenerateResult ignored = RootKeyGenerator.generate(dir, "enc-key", false)) {
            try (RootKeyManager km = RootKeyManager.fromProperties(props)) {
                // 二进制
                byte[] data = new byte[1024];
                new java.util.Random(42).nextBytes(data);
                assertArrayEquals(data, km.decrypt(km.encrypt(data)));
                // 中文文本 + Base64
                String secret = "机密数据-../../_🤫-AES256";
                assertEquals(secret, km.decryptFromBase64(km.encryptToBase64(secret)));
                // 空输入
                assertArrayEquals(new byte[0], km.decrypt(km.encrypt(new byte[0])));
            }
        }
    }

    @Test
    void freshCiphertextEachTimeButAllDecrypt(@org.junit.jupiter.api.io.TempDir Path dir) throws Exception {
        try (RootKeyGenerator.GenerateResult ignored = RootKeyGenerator.generate(dir, "iv-key", false)) {
            RootKeyConfig cfg = RootKeyConfig.builder()
                    .a(dir.resolve("a.comp")).b(dir.resolve("b.comp"))
                    .c(dir.resolve("c.comp")).d(dir.resolve("d.comp")).build();
            try (RootKeyManager km = new RootKeyManager(cfg)) {
                byte[] pt = "same plaintext".getBytes(StandardCharsets.UTF_8);
                byte[] c1 = km.encrypt(pt);
                byte[] c2 = km.encrypt(pt);
                assertFalse(Arrays.equals(c1, c2), "随机 IV 下两次密文应不同");
                assertArrayEquals(pt, km.decrypt(c1));
                assertArrayEquals(pt, km.decrypt(c2));
            }
        }
    }

    @Test
    void tamperedComponentFileRejected(@org.junit.jupiter.api.io.TempDir Path dir) throws Exception {
        RootKeyGenerator.generate(dir, "tamper-key", false).close();
        Path aFile = dir.resolve("a.comp");
        String content = new String(Files.readAllBytes(aFile), StandardCharsets.UTF_8);
        // 篡改 material 的一个字符（保持 Base64 合法）
        String tampered = content.replaceAll("(?m)^material=(.{6})", "material=XXXXXX");
        Files.write(aFile, tampered.getBytes(StandardCharsets.UTF_8));
        RootKeyException ex = assertThrows(RootKeyException.class,
                () -> ComponentFile.load(aFile));
        assertTrue(ex.getMessage().contains("校验和不匹配"), ex.getMessage());
    }

    @Test
    void mixedGenerationComponentsRejected(@org.junit.jupiter.api.io.TempDir Path dir) throws Exception {
        Path other = dir.resolve("other");
        RootKeyGenerator.generate(dir, "key-A", false).close();
        RootKeyGenerator.generate(other, "key-B", false).close();
        // 混入另一批次的组件 → KCV 校验必须失败
        RootKeyException ex = assertThrows(RootKeyException.class, () ->
                RootKeyRestorer.restore(
                        dir.resolve("a.comp"), other.resolve("b.comp"),
                        dir.resolve("c.comp"), dir.resolve("d.comp")));
        assertTrue(ex.getMessage().contains("KCV") || ex.getMessage().contains("keyId"), ex.getMessage());
    }

    @Test
    void duplicateComponentRejected(@org.junit.jupiter.api.io.TempDir Path dir) throws Exception {
        RootKeyGenerator.generate(dir, "dup-key", false).close();
        RootKeyException ex = assertThrows(RootKeyException.class, () ->
                RootKeyRestorer.restore(
                        dir.resolve("a.comp"), dir.resolve("a.comp"),
                        dir.resolve("b.comp"), dir.resolve("c.comp")));
        assertTrue(ex.getMessage().contains("标签"), ex.getMessage());
    }

    @Test
    void corruptedCiphertextRejected(@org.junit.jupiter.api.io.TempDir Path dir) throws Exception {
        try (RootKeyGenerator.GenerateResult ignored = RootKeyGenerator.generate(dir, "gcm-key", false)) {
            RootKeyConfig cfg = RootKeyConfig.builder()
                    .a(dir.resolve("a.comp")).b(dir.resolve("b.comp"))
                    .c(dir.resolve("c.comp")).d(dir.resolve("d.comp")).build();
            try (RootKeyManager km = new RootKeyManager(cfg)) {
                byte[] ct = km.encrypt("hello".getBytes(StandardCharsets.UTF_8));
                ct[ct.length - 1] ^= 0x01; // 翻转密文最后一个比特
                RootKeyException ex = assertThrows(RootKeyException.class, () -> km.decrypt(ct));
                assertTrue(ex.getMessage().contains("篡改") || ex.getMessage().contains("解密失败"), ex.getMessage());
            }
        }
    }

    @Test
    void configFromFileAndSystemPropertyOverride(@org.junit.jupiter.api.io.TempDir Path dir) throws Exception {
        try (RootKeyGenerator.GenerateResult ignored = RootKeyGenerator.generate(dir, "cfg-key", false)) {
            Path cfgFile = dir.resolve("rootkey.properties");
            Properties props = new Properties();
            props.setProperty(RootKeyConfig.KEY_A, dir.resolve("a.comp").toString());
            props.setProperty(RootKeyConfig.KEY_B, dir.resolve("b.comp").toString());
            props.setProperty(RootKeyConfig.KEY_C, dir.resolve("c.comp").toString());
            props.setProperty(RootKeyConfig.KEY_D, dir.resolve("d.comp").toString());
            try (java.io.Writer w = Files.newBufferedWriter(cfgFile, StandardCharsets.UTF_8)) {
                props.store(w, "test");
            }
            // 配置文件直读
            try (RootKeyManager km = RootKeyManager.fromConfigFile(cfgFile)) {
                assertEquals("cfg-key", km.keyId());
            }
            // 系统属性覆盖：把 a 指向 b 的文件 → 标签校验失败（证明覆盖生效）
            System.setProperty(RootKeyConfig.KEY_A, dir.resolve("b.comp").toString());
            try {
                try (RootKeyManager km = RootKeyManager.fromConfigFile(cfgFile)) {
                    RootKeyException ex = assertThrows(RootKeyException.class, km::keyId);
                    assertTrue(ex.getMessage().contains("标签"), ex.getMessage());
                }
            } finally {
                System.clearProperty(RootKeyConfig.KEY_A);
            }
        }
    }

    @Test
    void manifestKcvMatchesRestore(@org.junit.jupiter.api.io.TempDir Path dir) throws Exception {
        try (RootKeyGenerator.GenerateResult r = RootKeyGenerator.generate(dir, "mani-key", false)) {
            Properties manifest = new Properties();
            try (java.io.Reader reader = Files.newBufferedReader(r.manifestPath(), StandardCharsets.UTF_8)) {
                manifest.load(reader);
            }
            RootKeySecret s = RootKeyRestorer.restore(
                    dir.resolve("a.comp"), dir.resolve("b.comp"),
                    dir.resolve("c.comp"), dir.resolve("d.comp"));
            assertEquals(manifest.getProperty("kcv").toLowerCase(), s.kcvHex());
            s.destroy();
        }
    }

}
