package com.metrace.rootkey;

/**
 * 根密钥工具包的全局常量。
 */
public final class RootKeyConstants {

    /** 工具版本号 */
    public static final String TOOL_VERSION = "2.0.0";

    /** 根密钥长度：32 字节 = 256 位（AES-256） */
    public static final int ROOT_KEY_LENGTH_BYTES = 32;

    /** KCV（密钥校验值）长度：SHA-256 的前 8 字节 */
    public static final int KCV_LENGTH_BYTES = 8;

    /** 四个组件的标签：a / b / c / d */
    public static final char[] COMPONENT_LABELS = {'a', 'b', 'c', 'd'};

    /** 组件文件格式版本 */
    public static final int FILE_FORMAT_VERSION = 1;

    /** 组件文件的默认扩展名（根密钥材料以 .txt 文本文件承载） */
    public static final String COMPONENT_FILE_SUFFIX = ".txt";

    /** 算法标识 */
    public static final String ALGORITHM = "AES";

    /** keyId / 工作密钥名称等标识符的统一命名规则 */
    public static final java.util.regex.Pattern NAME_PATTERN =
            java.util.regex.Pattern.compile("^[A-Za-z0-9._-]{1,64}$");

    /** 工作密钥文件的默认扩展名（JSON 格式，一个文件可存多个工作密钥） */
    public static final String WORKKEY_FILE_SUFFIX = ".json";

    private RootKeyConstants() {
    }
}
