package com.metrace.rootkey;

import com.metrace.rootkey.config.RootKeyConfig;
import com.metrace.rootkey.core.RootKeyGenerator;
import com.metrace.rootkey.core.RootKeyRestorer;
import com.metrace.rootkey.core.RootKeySecret;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.util.Arrays;

import static org.junit.jupiter.api.Assertions.*;

/**
 * 稳定性专项测试：还原必须是纯函数；不同 Manager 实例、跨次数结果一致。
 */
class StabilityTest {

    @Test
    void restore200TimesAlwaysIdentical(@TempDir Path dir) throws Exception {
        String expectedKcv;
        byte[] expectedKey;
        try (RootKeyGenerator.GenerateResult r = RootKeyGenerator.generate(dir, "stable-key", false)) {
            expectedKcv = r.kcvHex();
            expectedKey = r.secret().exportKey();
        }
        for (int i = 0; i < 200; i++) {
            RootKeySecret s = RootKeyRestorer.restore(
                    dir.resolve("a.comp"), dir.resolve("b.comp"),
                    dir.resolve("c.comp"), dir.resolve("d.comp"));
            assertEquals(expectedKcv, s.kcvHex(), "第 " + i + " 次 KCV 不一致");
            if (!Arrays.equals(expectedKey, s.exportKey())) {
                fail("第 " + i + " 次还原的根密钥不一致");
            }
            s.destroy();
        }
    }

    @Test
    void crossManagerEncryptDecrypt(@TempDir Path dir) throws Exception {
        try (RootKeyGenerator.GenerateResult ignored = RootKeyGenerator.generate(dir, "cross-key", false)) {
            RootKeyConfig cfg = RootKeyConfig.builder()
                    .a(dir.resolve("a.comp")).b(dir.resolve("b.comp"))
                    .c(dir.resolve("c.comp")).d(dir.resolve("d.comp")).build();
            byte[] pt = "跨实例解密".getBytes(StandardCharsets.UTF_8);
            byte[] ct;
            try (RootKeyManager producer = new RootKeyManager(cfg)) {
                ct = producer.encrypt(pt);
            }
            // 模拟另一进程/另一实例：从同一组组件还原后解密
            try (RootKeyManager consumer = new RootKeyManager(cfg)) {
                assertArrayEquals(pt, consumer.decrypt(ct));
            }
        }
    }

    @Test
    void reloadFilesFromDiskEachRestoreIsStable(@TempDir Path dir) throws Exception {
        // 模拟服务器重启后重新从磁盘加载组件：结果必须一致
        RootKeyConfig cfg;
        String b64;
        try (RootKeyGenerator.GenerateResult ignored = RootKeyGenerator.generate(dir, "reboot-key", false)) {
            cfg = RootKeyConfig.builder()
                    .a(dir.resolve("a.comp")).b(dir.resolve("b.comp"))
                    .c(dir.resolve("c.comp")).d(dir.resolve("d.comp")).build();
        }
        try (RootKeyManager km = new RootKeyManager(cfg)) {
            b64 = km.encryptToBase64("重启后仍可解密");
        }
        try (RootKeyManager km2 = new RootKeyManager(cfg)) {
            assertEquals("重启后仍可解密", km2.decryptFromBase64(b64));
        }
    }
}
