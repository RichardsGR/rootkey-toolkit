package com.metrace.rootkey;

/**
 * 根密钥工具统一运行时异常。
 * 所有可预期的业务错误（配置缺失、组件损坏、校验失败、解密失败等）都以此异常抛出。
 */
public class RootKeyException extends RuntimeException {

    private static final long serialVersionUID = 1L;

    public RootKeyException(String message) {
        super(message);
    }

    public RootKeyException(String message, Throwable cause) {
        super(message, cause);
    }
}
