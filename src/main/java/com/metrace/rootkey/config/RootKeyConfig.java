package com.metrace.rootkey.config;

import com.metrace.rootkey.RootKeyException;

import java.io.IOException;
import java.io.Reader;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.Locale;
import java.util.Properties;

/**
 * 根密钥组件位置配置（abcd 位置由配置项承载）。
 *
 * <p>配置文件（properties 格式）示例：</p>
 * <pre>
 *   rootkey.component.a.path=/etc/rootkey/a.comp
 *   rootkey.component.b.path=/etc/rootkey/b.comp
 *   rootkey.component.c.path=/etc/rootkey/c.comp
 *   rootkey.component.d.path=/etc/rootkey/d.comp
 * </pre>
 *
 * <p>优先级（高到低）：JVM 系统属性 &gt; 环境变量 &gt; 配置文件。
 * 环境变量命名规则：小写点号转大写下划线，例如
 * {@code rootkey.component.a.path} → {@code ROOTKEY_COMPONENT_A_PATH}。</p>
 */
public final class RootKeyConfig {

    public static final String KEY_A = "rootkey.component.a.path";
    public static final String KEY_B = "rootkey.component.b.path";
    public static final String KEY_C = "rootkey.component.c.path";
    public static final String KEY_D = "rootkey.component.d.path";

    private final Path pathA;
    private final Path pathB;
    private final Path pathC;
    private final Path pathD;

    private RootKeyConfig(Builder b) {
        if (isBlank(b.a) || isBlank(b.b) || isBlank(b.c) || isBlank(b.d)) {
            throw new RootKeyException("组件配置不完整，需要提供 a/b/c/d 四个路径（配置项 "
                    + KEY_A + " ~ " + KEY_D + "）");
        }
        this.pathA = Paths.get(b.a);
        this.pathB = Paths.get(b.b);
        this.pathC = Paths.get(b.c);
        this.pathD = Paths.get(b.d);
    }

    private static boolean isBlank(String s) {
        return s == null || s.trim().isEmpty();
    }

    public Path aPath() {
        return pathA;
    }

    public Path bPath() {
        return pathB;
    }

    public Path cPath() {
        return pathC;
    }

    public Path dPath() {
        return pathD;
    }

    /**
     * 从配置文件加载，并应用系统属性/环境变量覆盖。
     */
    public static RootKeyConfig load(Path configFile) {
        Properties props = new Properties();
        try (Reader r = Files.newBufferedReader(configFile, StandardCharsets.UTF_8)) {
            props.load(r);
        } catch (IOException e) {
            throw new RootKeyException("无法读取配置文件: " + configFile, e);
        }
        for (String key : new String[]{KEY_A, KEY_B, KEY_C, KEY_D}) {
            String override = System.getProperty(key);
            if (isBlank(override)) {
                override = System.getenv(toEnvName(key));
            }
            if (!isBlank(override)) {
                props.setProperty(key, override.trim());
            }
        }
        return fromProperties(props);
    }

    /** 环境变量名：rootkey.component.a.path -&gt; ROOTKEY_COMPONENT_A_PATH */
    public static String toEnvName(String key) {
        return key.toUpperCase(Locale.ROOT).replace('.', '_');
    }

    /**
     * 从 Properties 构建（缺项时抛出异常并列出缺失项）。
     */
    public static RootKeyConfig fromProperties(Properties props) {
        Builder b = builder();
        b.a(required(props, KEY_A));
        b.b(required(props, KEY_B));
        b.c(required(props, KEY_C));
        b.d(required(props, KEY_D));
        return b.build();
    }

    private static String required(Properties props, String key) {
        String v = props.getProperty(key);
        if (isBlank(v)) {
            throw new RootKeyException("缺少配置项: " + key);
        }
        return v.trim();
    }

    /** 导出为 Properties（可用于生成示例配置） */
    public Properties toProperties() {
        Properties p = new Properties();
        p.setProperty(KEY_A, pathA.toString());
        p.setProperty(KEY_B, pathB.toString());
        p.setProperty(KEY_C, pathC.toString());
        p.setProperty(KEY_D, pathD.toString());
        return p;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static final class Builder {
        private String a;
        private String b;
        private String c;
        private String d;

        public Builder a(Path path) {
            return a(path.toString());
        }

        public Builder a(String path) {
            this.a = path;
            return this;
        }

        public Builder b(Path path) {
            return b(path.toString());
        }

        public Builder b(String path) {
            this.b = path;
            return this;
        }

        public Builder c(Path path) {
            return c(path.toString());
        }

        public Builder c(String path) {
            this.c = path;
            return this;
        }

        public Builder d(Path path) {
            return d(path.toString());
        }

        public Builder d(String path) {
            this.d = path;
            return this;
        }

        public RootKeyConfig build() {
            return new RootKeyConfig(this);
        }
    }
}
