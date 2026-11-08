package com.metrace.rootkey.internal;

import com.metrace.rootkey.RootKeyException;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * 极简 JSON 工具（纯 JDK，无第三方依赖）。
 *
 * <p>{@link #parse} 支持任意 JSON：对象→LinkedHashMap、数组→ArrayList、
 * 字符串/布尔/null、数字→BigDecimal（无浮点歧义）。{@link #write} 做对应的
 * 带 2 空格缩进的序列化。供 Web 管理台 API 与工作密钥 JSON 文件共用。</p>
 */
public final class Json {

    private Json() {
    }

    /** 解析任意 JSON 文本 */
    public static Object parse(String s) {
        int[] pos = new int[]{0};
        Object v = parseValue(s, pos);
        skipWs(s, pos);
        if (pos[0] != s.length()) {
            throw new RootKeyException("JSON 解析错误：位置 " + pos[0] + " 有多余内容");
        }
        return v;
    }

    /** 解析扁平 JSON 对象为 Map&lt;String,String&gt;（布尔/数字转为字符串形式；Web 请求体用） */
    @SuppressWarnings("unchecked")
    public static Map<String, String> parseFlatObject(String json) {
        Object o = parse(json);
        if (!(o instanceof Map)) {
            throw new RootKeyException("JSON 请求体必须是对象");
        }
        Map<String, String> out = new LinkedHashMap<String, String>();
        for (Map.Entry<String, Object> e : ((Map<String, Object>) o).entrySet()) {
            Object v = e.getValue();
            out.put(e.getKey(), v == null ? null : v instanceof String ? (String) v : String.valueOf(v));
        }
        return out;
    }

    /** 序列化为带缩进的 JSON 文本 */
    public static String write(Object o) {
        StringBuilder sb = new StringBuilder(256);
        writeValue(sb, o, 0);
        return sb.toString();
    }

    // ------------------------------------------------------------------ parse

    private static Object parseValue(String s, int[] pos) {
        skipWs(s, pos);
        char c = peek(s, pos);
        switch (c) {
            case '{': return parseObject(s, pos);
            case '[': return parseArray(s, pos);
            case '"': return parseString(s, pos);
            default:  return parseLiteral(s, pos);
        }
    }

    private static Map<String, Object> parseObject(String s, int[] pos) {
        expect(s, pos, '{');
        Map<String, Object> out = new LinkedHashMap<String, Object>();
        skipWs(s, pos);
        if (peek(s, pos) == '}') {
            pos[0]++;
            return out;
        }
        while (true) {
            skipWs(s, pos);
            String key = parseString(s, pos);
            skipWs(s, pos);
            expect(s, pos, ':');
            out.put(key, parseValue(s, pos));
            skipWs(s, pos);
            char d = peek(s, pos);
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

    private static List<Object> parseArray(String s, int[] pos) {
        expect(s, pos, '[');
        List<Object> out = new ArrayList<Object>();
        skipWs(s, pos);
        if (peek(s, pos) == ']') {
            pos[0]++;
            return out;
        }
        while (true) {
            out.add(parseValue(s, pos));
            skipWs(s, pos);
            char d = peek(s, pos);
            if (d == ',') {
                pos[0]++;
            } else if (d == ']') {
                pos[0]++;
                return out;
            } else {
                throw new RootKeyException("JSON 解析错误：位置 " + pos[0] + " 缺少 , 或 ]");
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

    private static Object parseLiteral(String s, int[] pos) {
        int start = pos[0];
        while (pos[0] < s.length()) {
            char c = s.charAt(pos[0]);
            if (c == ',' || c == '}' || c == ']' || c == ' ' || c == '\t' || c == '\r' || c == '\n') {
                break;
            }
            pos[0]++;
        }
        if (pos[0] == start) {
            throw new RootKeyException("JSON 解析错误：位置 " + start + " 缺少值");
        }
        String token = s.substring(start, pos[0]);
        if ("true".equals(token)) {
            return Boolean.TRUE;
        }
        if ("false".equals(token)) {
            return Boolean.FALSE;
        }
        if ("null".equals(token)) {
            return null;
        }
        try {
            return new java.math.BigDecimal(token);
        } catch (NumberFormatException e) {
            throw new RootKeyException("JSON 解析错误：非法字面量 '" + token + "'");
        }
    }

    // ------------------------------------------------------------------ write

    private static void writeValue(StringBuilder sb, Object o, int indent) {
        if (o == null) {
            sb.append("null");
        } else if (o instanceof String) {
            sb.append('"').append(escape((String) o)).append('"');
        } else if (o instanceof Number || o instanceof Boolean) {
            sb.append(o);
        } else if (o instanceof Map) {
            writeMap(sb, (Map<?, ?>) o, indent);
        } else if (o instanceof List) {
            writeList(sb, (List<?>) o, indent);
        } else {
            throw new RootKeyException("无法序列化的类型: " + o.getClass().getName());
        }
    }

    private static void writeMap(StringBuilder sb, Map<?, ?> m, int indent) {
        if (m.isEmpty()) {
            sb.append("{}");
            return;
        }
        sb.append("{\n");
        int i = 0;
        for (Map.Entry<?, ?> e : m.entrySet()) {
            indent(sb, indent + 1);
            sb.append('"').append(escape(String.valueOf(e.getKey()))).append("\": ");
            writeValue(sb, e.getValue(), indent + 1);
            if (++i < m.size()) {
                sb.append(',');
            }
            sb.append('\n');
        }
        indent(sb, indent);
        sb.append('}');
    }

    private static void writeList(StringBuilder sb, List<?> l, int indent) {
        if (l.isEmpty()) {
            sb.append("[]");
            return;
        }
        sb.append("[\n");
        for (int i = 0; i < l.size(); i++) {
            indent(sb, indent + 1);
            writeValue(sb, l.get(i), indent + 1);
            if (i < l.size() - 1) {
                sb.append(',');
            }
            sb.append('\n');
        }
        indent(sb, indent);
        sb.append(']');
    }

    private static void indent(StringBuilder sb, int n) {
        for (int i = 0; i < n; i++) {
            sb.append("  ");
        }
    }

    // ------------------------------------------------------------------ escape

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
