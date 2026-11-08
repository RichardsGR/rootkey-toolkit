package com.metrace.rootkey.webui;

import com.metrace.rootkey.RootKeyException;

import java.util.LinkedHashMap;
import java.util.Map;

/**
 * 极简 JSON 工具（仅满足本管理页面的需要，无第三方依赖）。
 *
 * <p>请求体是扁平对象（string/number/boolean），{@link #parseFlatObject} 解析为
 * Map&lt;String,String&gt;；布尔以 "true"/"false" 字符串表示。响应侧用
 * {@link #escape} 手工拼接。</p>
 */
public final class Json {

    private Json() {
    }

    /** 解析扁平 JSON 对象（不支持嵌套/数组——本工具的请求用不到） */
    public static Map<String, String> parseFlatObject(String json) {
        int[] pos = new int[]{0};
        Map<String, String> out = new LinkedHashMap<String, String>();
        skipWs(json, pos);
        expect(json, pos, '{');
        skipWs(json, pos);
        if (peek(json, pos) == '}') {
            pos[0]++;
            return out;
        }
        while (true) {
            skipWs(json, pos);
            String key = parseString(json, pos);
            skipWs(json, pos);
            expect(json, pos, ':');
            skipWs(json, pos);
            char c = peek(json, pos);
            String value;
            if (c == '"') {
                value = parseString(json, pos);
            } else {
                value = parseLiteral(json, pos); // true/false/null/数字，原样截取
            }
            out.put(key, value);
            skipWs(json, pos);
            char d = peek(json, pos);
            if (d == ',') {
                pos[0]++;
            } else if (d == '}') {
                pos[0]++;
                return out;
            } else {
                throw new RootKeyException("JSON 解析错误：位置 " + pos[0] + " 缺少 , 或 }");
            }
        }
    }

    private static void skipWs(String s, int[] pos) {
        while (pos[0] < s.length()) {
            char c = s.charAt(pos[0]);
            if (c == ' ' || c == '\t' || c == '\r' || c == '\n') {
                pos[0]++;
            } else {
                break;
            }
        }
    }

    private static char peek(String s, int[] pos) {
        if (pos[0] >= s.length()) {
            throw new RootKeyException("JSON 解析错误：意外结束");
        }
        return s.charAt(pos[0]);
    }

    private static void expect(String s, int[] pos, char c) {
        if (peek(s, pos) != c) {
            throw new RootKeyException("JSON 解析错误：位置 " + pos[0] + " 期望 '" + c + "'");
        }
        pos[0]++;
    }

    private static String parseString(String s, int[] pos) {
        expect(s, pos, '"');
        StringBuilder sb = new StringBuilder();
        while (true) {
            char c = peek(s, pos);
            pos[0]++;
            if (c == '"') {
                return sb.toString();
            }
            if (c == '\\') {
                char e = peek(s, pos);
                pos[0]++;
                switch (e) {
                    case '"': sb.append('"'); break;
                    case '\\': sb.append('\\'); break;
                    case '/': sb.append('/'); break;
                    case 'b': sb.append('\b'); break;
                    case 'f': sb.append('\f'); break;
                    case 'n': sb.append('\n'); break;
                    case 'r': sb.append('\r'); break;
                    case 't': sb.append('\t'); break;
                    case 'u':
                        if (pos[0] + 4 > s.length()) {
                            throw new RootKeyException("JSON 解析错误：\\u 转义不完整");
                        }
                        sb.append((char) Integer.parseInt(s.substring(pos[0], pos[0] + 4), 16));
                        pos[0] += 4;
                        break;
                    default:
                        throw new RootKeyException("JSON 解析错误：非法转义 \\" + e);
                }
            } else {
                sb.append(c);
            }
        }
    }

    private static String parseLiteral(String s, int[] pos) {
        int start = pos[0];
        while (pos[0] < s.length()) {
            char c = s.charAt(pos[0]);
            if (c == ',' || c == '}' || c == ' ' || c == '\t' || c == '\r' || c == '\n') {
                break;
            }
            pos[0]++;
        }
        if (pos[0] == start) {
            throw new RootKeyException("JSON 解析错误：位置 " + start + " 缺少值");
        }
        return s.substring(start, pos[0]);
    }

    /** 转义为可嵌入 JSON 字符串字面量的内容（不含首尾引号） */
    public static String escape(String s) {
        if (s == null) {
            return "";
        }
        StringBuilder sb = new StringBuilder(s.length() + 16);
        for (int i = 0; i < s.length(); i++) {
            char c = s.charAt(i);
            switch (c) {
                case '"': sb.append("\\\""); break;
                case '\\': sb.append("\\\\"); break;
                case '\n': sb.append("\\n"); break;
                case '\r': sb.append("\\r"); break;
                case '\t': sb.append("\\t"); break;
                case '<': sb.append("\\u003c"); break;
                case '>': sb.append("\\u003e"); break;
                default:
                    if (c < 0x20) {
                        sb.append(String.format("\\u%04x", (int) c));
                    } else {
                        sb.append(c);
                    }
            }
        }
        return sb.toString();
    }
}
