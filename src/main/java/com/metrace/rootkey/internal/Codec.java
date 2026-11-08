package com.metrace.rootkey.internal;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Base64;

/**
 * 内部编解码/摘要工具（纯 JDK，无第三方依赖）。
 */
public final class Codec {

    private static final char[] HEX = "0123456789abcdef".toCharArray();

    private Codec() {
    }

    /** 字节数组转小写十六进制 */
    public static String toHex(byte[] bytes) {
        char[] out = new char[bytes.length * 2];
        for (int i = 0; i < bytes.length; i++) {
            int v = bytes[i] & 0xFF;
            out[i * 2] = HEX[v >>> 4];
            out[i * 2 + 1] = HEX[v & 0x0F];
        }
        return new String(out);
    }

    /** 拼接所有入参后计算 SHA-256 */
    public static byte[] sha256(byte[]... parts) {
        try {
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            for (byte[] p : parts) {
                md.update(p);
            }
            return md.digest();
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException("JDK 不提供 SHA-256，环境异常", e);
        }
    }

    /** 字符串 SHA-256 的十六进制表示（UTF-8） */
    public static String sha256Hex(String s) {
        return toHex(sha256(s.getBytes(StandardCharsets.UTF_8)));
    }

    /** 将若干等长字节数组按位异或（用于 4-of-4 分片的派生与还原，顺序无关） */
    public static byte[] xorAll(byte[]... arrays) {
        if (arrays == null || arrays.length == 0) {
            throw new IllegalArgumentException("xorAll 需要至少一个输入");
        }
        int len = arrays[0].length;
        byte[] out = new byte[len];
        for (byte[] arr : arrays) {
            if (arr.length != len) {
                throw new IllegalArgumentException("xorAll 输入长度不一致: " + arr.length + " != " + len);
            }
            for (int i = 0; i < len; i++) {
                out[i] ^= arr[i];
            }
        }
        return out;
    }

    /** Base64 编码（无换行） */
    public static String b64(byte[] bytes) {
        return Base64.getEncoder().encodeToString(bytes);
    }

    /** 读尽输入流（Java 8 兼容实现） */
    public static byte[] readAll(InputStream in) throws IOException {
        ByteArrayOutputStream bos = new ByteArrayOutputStream();
        byte[] buf = new byte[8192];
        int n;
        while ((n = in.read(buf)) > 0) {
            bos.write(buf, 0, n);
        }
        return bos.toByteArray();
    }
}
