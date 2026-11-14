package com.javashield.core.json;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * Minimal, dependency-free JSON reader/writer with deterministic output.
 *
 * <p>The data model produced by {@link #parse(String)} is:</p>
 * <ul>
 *   <li>JSON object &rarr; {@link LinkedHashMap} (insertion order preserved while parsing)</li>
 *   <li>JSON array &rarr; {@link ArrayList}</li>
 *   <li>integer number &rarr; {@link Long}, decimal/exponent number &rarr; {@link Double}</li>
 *   <li>string &rarr; {@link String}, {@code true}/{@code false} &rarr; {@link Boolean}, {@code null} &rarr; {@code null}</li>
 * </ul>
 *
 * <p>{@link #canonical(Object)} is intended to be used as the byte-exact payload for
 * signatures: keys are sorted with {@link String#compareTo(String)}, no insignificant
 * whitespace is emitted, and every non-ASCII code unit is escaped, so the result does not
 * depend on the JVM, the default locale or the platform charset.</p>
 *
 * <p>Note: because fractions are serialized with {@link Double#toString(double)}, the
 * binary representation is used. Signed payloads should avoid decimal numbers; use integer
 * values (which are written verbatim from {@link Long}) whenever possible.</p>
 */
public final class Json {

    private static final char[] HEX = "0123456789abcdef".toCharArray();

    private Json() {
    }

    // ------------------------------------------------------------------
    // Parsing
    // ------------------------------------------------------------------

    /**
     * Parses a complete JSON document.
     *
     * @param text JSON text, surrounding whitespace allowed
     * @return {@link Map}, {@link List}, {@link String}, {@link Long}, {@link Double},
     *         {@link Boolean} or {@code null}
     * @throws IllegalArgumentException if the input is not a single valid JSON value
     */
    public static Object parse(String text) {
        if (text == null) {
            throw new IllegalArgumentException("JSON text must not be null");
        }
        Parser parser = new Parser(text);
        parser.skipWhitespace();
        Object value = parser.readValue();
        parser.skipWhitespace();
        if (parser.pos < text.length()) {
            throw parser.error("Unexpected trailing character '" + text.charAt(parser.pos) + "'");
        }
        return value;
    }

    /**
     * Parses a JSON document and requires the top level value to be an object.
     *
     * @throws IllegalArgumentException if the input is invalid or is not a JSON object
     */
    public static Map<String, Object> parseObject(String text) {
        Object value = parse(text);
        if (!(value instanceof Map)) {
            throw new IllegalArgumentException("Expected a JSON object but found " + describe(value));
        }
        @SuppressWarnings("unchecked")
        Map<String, Object> object = (Map<String, Object>) value;
        return object;
    }

    // ------------------------------------------------------------------
    // Serialization
    // ------------------------------------------------------------------

    /**
     * Serializes a value deterministically: sorted object keys, no whitespace and
     * pure-ASCII output. The same value always produces the identical string on every
     * JVM and under every locale.
     */
    public static String canonical(Object value) {
        StringBuilder out = new StringBuilder(64);
        writeCompact(out, value);
        return out.toString();
    }

    /**
     * Serializes a value like {@link #canonical(Object)} but with two-space indentation
     * and one array element per line. The output is still pure ASCII and can be parsed
     * back by {@link #parse(String)}.
     */
    public static String pretty(Object value) {
        StringBuilder out = new StringBuilder(128);
        writePretty(out, value, 0);
        return out.toString();
    }

    // ------------------------------------------------------------------
    // Accessors
    // ------------------------------------------------------------------

    /** Returns the value as a {@link String}, rejecting every other type. */
    public static String asString(Object value) {
        if (value instanceof String) {
            return (String) value;
        }
        throw new IllegalArgumentException("Expected a string but found " + describe(value));
    }

    /** Returns the value as a {@code long}; accepts {@link Long}, {@link Integer} and numeric strings. */
    public static long asLong(Object value) {
        if (value instanceof Long) {
            return (Long) value;
        }
        if (value instanceof Integer) {
            return ((Integer) value).longValue();
        }
        if (value instanceof String) {
            try {
                return Long.parseLong(((String) value).trim());
            } catch (NumberFormatException e) {
                throw new IllegalArgumentException("Expected a long but found \"" + value + "\"", e);
            }
        }
        throw new IllegalArgumentException("Expected a long but found " + describe(value));
    }

    /** Returns the value as a {@code boolean}, rejecting every other type. */
    public static boolean asBoolean(Object value) {
        if (value instanceof Boolean) {
            return (Boolean) value;
        }
        throw new IllegalArgumentException("Expected a boolean but found " + describe(value));
    }

    // ------------------------------------------------------------------
    // Compact writer
    // ------------------------------------------------------------------

    private static void writeCompact(StringBuilder out, Object value) {
        if (value == null) {
            out.append("null");
            return;
        }
        if (value instanceof String) {
            writeString(out, (String) value);
            return;
        }
        if (value instanceof Boolean) {
            out.append(((Boolean) value).booleanValue() ? "true" : "false");
            return;
        }
        if (value instanceof Long || value instanceof Integer
                || value instanceof Short || value instanceof Byte) {
            out.append(((Number) value).longValue());
            return;
        }
        if (value instanceof Double || value instanceof Float) {
            out.append(Double.toString(((Number) value).doubleValue()));
            return;
        }
        if (value instanceof Map) {
            @SuppressWarnings("unchecked")
            Map<Object, Object> map = (Map<Object, Object>) value;
            List<String> keys = sortedKeys(map);
            if (keys.isEmpty()) {
                out.append("{}");
                return;
            }
            out.append('{');
            for (int i = 0; i < keys.size(); i++) {
                if (i > 0) {
                    out.append(',');
                }
                String key = keys.get(i);
                writeString(out, key);
                out.append(':');
                writeCompact(out, map.get(key));
            }
            out.append('}');
            return;
        }
        if (value instanceof List) {
            List<?> list = (List<?>) value;
            if (list.isEmpty()) {
                out.append("[]");
                return;
            }
            out.append('[');
            for (int i = 0; i < list.size(); i++) {
                if (i > 0) {
                    out.append(',');
                }
                writeCompact(out, list.get(i));
            }
            out.append(']');
            return;
        }
        throw new IllegalArgumentException(
                "Unsupported type for canonical JSON: " + value.getClass().getName());
    }

    // ------------------------------------------------------------------
    // Pretty writer
    // ------------------------------------------------------------------

    private static void writePretty(StringBuilder out, Object value, int depth) {
        if (value == null) {
            out.append("null");
            return;
        }
        if (value instanceof String) {
            writeString(out, (String) value);
            return;
        }
        if (value instanceof Boolean) {
            out.append(((Boolean) value).booleanValue() ? "true" : "false");
            return;
        }
        if (value instanceof Long || value instanceof Integer
                || value instanceof Short || value instanceof Byte) {
            out.append(((Number) value).longValue());
            return;
        }
        if (value instanceof Double || value instanceof Float) {
            out.append(Double.toString(((Number) value).doubleValue()));
            return;
        }
        if (value instanceof Map) {
            @SuppressWarnings("unchecked")
            Map<Object, Object> map = (Map<Object, Object>) value;
            List<String> keys = sortedKeys(map);
            if (keys.isEmpty()) {
                out.append("{}");
                return;
            }
            out.append("{\n");
            for (int i = 0; i < keys.size(); i++) {
                String key = keys.get(i);
                indent(out, depth + 1);
                writeString(out, key);
                out.append(": ");
                writePretty(out, map.get(key), depth + 1);
                if (i < keys.size() - 1) {
                    out.append(',');
                }
                out.append('\n');
            }
            indent(out, depth);
            out.append('}');
            return;
        }
        if (value instanceof List) {
            List<?> list = (List<?>) value;
            if (list.isEmpty()) {
                out.append("[]");
                return;
            }
            out.append("[\n");
            for (int i = 0; i < list.size(); i++) {
                indent(out, depth + 1);
                writePretty(out, list.get(i), depth + 1);
                if (i < list.size() - 1) {
                    out.append(',');
                }
                out.append('\n');
            }
            indent(out, depth);
            out.append(']');
            return;
        }
        throw new IllegalArgumentException(
                "Unsupported type for pretty JSON: " + value.getClass().getName());
    }

    private static void indent(StringBuilder out, int depth) {
        for (int i = 0; i < depth; i++) {
            out.append("  ");
        }
    }

    // ------------------------------------------------------------------
    // Shared helpers
    // ------------------------------------------------------------------

    private static List<String> sortedKeys(Map<Object, Object> map) {
        List<String> keys = new ArrayList<String>(map.size());
        for (Object key : map.keySet()) {
            if (!(key instanceof String)) {
                throw new IllegalArgumentException("JSON object keys must be strings but found "
                        + (key == null ? "null" : key.getClass().getName()));
            }
            keys.add((String) key);
        }
        keys.sort(null);
        return keys;
    }

    private static void writeString(StringBuilder out, String s) {
        out.append('"');
        for (int i = 0; i < s.length(); i++) {
            char c = s.charAt(i);
            switch (c) {
                case '"':
                    out.append("\\\"");
                    break;
                case '\\':
                    out.append("\\\\");
                    break;
                case '\b':
                    out.append("\\b");
                    break;
                case '\f':
                    out.append("\\f");
                    break;
                case '\n':
                    out.append("\\n");
                    break;
                case '\r':
                    out.append("\\r");
                    break;
                case '\t':
                    out.append("\\t");
                    break;
                default:
                    if (c < 0x20 || c >= 0x7F) {
                        out.append("\\u");
                        out.append(HEX[(c >> 12) & 0xF]);
                        out.append(HEX[(c >> 8) & 0xF]);
                        out.append(HEX[(c >> 4) & 0xF]);
                        out.append(HEX[c & 0xF]);
                    } else {
                        out.append(c);
                    }
                    break;
            }
        }
        out.append('"');
    }

    private static String describe(Object value) {
        if (value == null) {
            return "null";
        }
        return value.getClass().getSimpleName() + " (" + value + ")";
    }

    // ------------------------------------------------------------------
    // Parser
    // ------------------------------------------------------------------

    private static final class Parser {

        private final String text;
        private int pos;

        Parser(String text) {
            this.text = text;
        }

        IllegalArgumentException error(String message) {
            return new IllegalArgumentException(message + " at index " + pos);
        }

        void skipWhitespace() {
            while (pos < text.length()) {
                char c = text.charAt(pos);
                if (c == ' ' || c == '\t' || c == '\n' || c == '\r') {
                    pos++;
                } else {
                    break;
                }
            }
        }

        Object readValue() {
            if (pos >= text.length()) {
                throw error("Unexpected end of input");
            }
            char c = text.charAt(pos);
            switch (c) {
                case '{':
                    return readObject();
                case '[':
                    return readArray();
                case '"':
                    return readString();
                case 't':
                    expect("true");
                    return Boolean.TRUE;
                case 'f':
                    expect("false");
                    return Boolean.FALSE;
                case 'n':
                    expect("null");
                    return null;
                default:
                    if (c == '-' || (c >= '0' && c <= '9')) {
                        return readNumber();
                    }
                    throw error("Unexpected character '" + c + "'");
            }
        }

        private Map<String, Object> readObject() {
            Map<String, Object> object = new LinkedHashMap<String, Object>();
            pos++; // '{'
            skipWhitespace();
            if (pos < text.length() && text.charAt(pos) == '}') {
                pos++;
                return object;
            }
            while (true) {
                skipWhitespace();
                if (pos >= text.length() || text.charAt(pos) != '"') {
                    throw error("Expected a string key in object");
                }
                String key = readString();
                skipWhitespace();
                if (pos >= text.length() || text.charAt(pos) != ':') {
                    throw error("Expected ':' after object key");
                }
                pos++;
                skipWhitespace();
                Object value = readValue();
                object.put(key, value);
                skipWhitespace();
                if (pos >= text.length()) {
                    throw error("Unexpected end of input inside object");
                }
                char c = text.charAt(pos);
                if (c == ',') {
                    pos++;
                } else if (c == '}') {
                    pos++;
                    return object;
                } else {
                    throw error("Expected ',' or '}' in object but found '" + c + "'");
                }
            }
        }

        private List<Object> readArray() {
            List<Object> array = new ArrayList<Object>();
            pos++; // '['
            skipWhitespace();
            if (pos < text.length() && text.charAt(pos) == ']') {
                pos++;
                return array;
            }
            while (true) {
                skipWhitespace();
                array.add(readValue());
                skipWhitespace();
                if (pos >= text.length()) {
                    throw error("Unexpected end of input inside array");
                }
                char c = text.charAt(pos);
                if (c == ',') {
                    pos++;
                } else if (c == ']') {
                    pos++;
                    return array;
                } else {
                    throw error("Expected ',' or ']' in array but found '" + c + "'");
                }
            }
        }

        private String readString() {
            StringBuilder sb = new StringBuilder();
            pos++; // opening quote
            while (true) {
                if (pos >= text.length()) {
                    throw error("Unterminated string");
                }
                char c = text.charAt(pos++);
                if (c == '"') {
                    return sb.toString();
                }
                if (c == '\\') {
                    if (pos >= text.length()) {
                        throw error("Unterminated escape sequence");
                    }
                    char escape = text.charAt(pos++);
                    switch (escape) {
                        case '"':
                            sb.append('"');
                            break;
                        case '\\':
                            sb.append('\\');
                            break;
                        case '/':
                            sb.append('/');
                            break;
                        case 'b':
                            sb.append('\b');
                            break;
                        case 'f':
                            sb.append('\f');
                            break;
                        case 'n':
                            sb.append('\n');
                            break;
                        case 'r':
                            sb.append('\r');
                            break;
                        case 't':
                            sb.append('\t');
                            break;
                        case 'u':
                            sb.append(readUnicodeEscape());
                            break;
                        default:
                            throw error("Invalid escape sequence '\\" + escape + "'");
                    }
                } else if (c < 0x20) {
                    throw error("Unescaped control character U+" + hex4(c) + " in string");
                } else {
                    sb.append(c);
                }
            }
        }

        /**
         * Reads the four hex digits of a backslash-u escape. Surrogate pairs are
         * reassembled naturally because each half is appended as its own UTF-16 code unit.
         */
        private char readUnicodeEscape() {
            if (pos + 4 > text.length()) {
                throw error("Incomplete unicode escape");
            }
            int value = 0;
            for (int i = 0; i < 4; i++) {
                char h = text.charAt(pos + i);
                int digit = hexValue(h);
                if (digit < 0) {
                    throw new IllegalArgumentException(
                            "Invalid hex digit '" + h + "' in unicode escape at index " + (pos + i));
                }
                value = (value << 4) | digit;
            }
            pos += 4;
            return (char) value;
        }

        private Object readNumber() {
            int start = pos;
            if (text.charAt(pos) == '-') {
                pos++;
                if (pos >= text.length()) {
                    throw error("Invalid number: digits expected after '-'");
                }
            }
            char first = text.charAt(pos);
            if (first == '0') {
                pos++;
            } else if (first >= '1' && first <= '9') {
                skipDigits();
            } else {
                throw error("Invalid number: unexpected character '" + first + "'");
            }
            boolean decimal = false;
            if (pos < text.length() && text.charAt(pos) == '.') {
                decimal = true;
                pos++;
                if (pos >= text.length() || !isDigit(text.charAt(pos))) {
                    throw error("Invalid number: digits expected after decimal point");
                }
                skipDigits();
            }
            if (pos < text.length() && (text.charAt(pos) == 'e' || text.charAt(pos) == 'E')) {
                decimal = true;
                pos++;
                if (pos < text.length() && (text.charAt(pos) == '+' || text.charAt(pos) == '-')) {
                    pos++;
                }
                if (pos >= text.length() || !isDigit(text.charAt(pos))) {
                    throw error("Invalid number: digits expected in exponent");
                }
                skipDigits();
            }
            String literal = text.substring(start, pos);
            if (!decimal) {
                try {
                    return Long.valueOf(literal);
                } catch (NumberFormatException overflow) {
                    // Integer literals that do not fit in a long degrade to double.
                }
            }
            double parsed = Double.parseDouble(literal);
            if (Double.isInfinite(parsed)) {
                pos = start;
                throw error("Number out of range: " + literal);
            }
            return Double.valueOf(parsed);
        }

        private void skipDigits() {
            while (pos < text.length() && isDigit(text.charAt(pos))) {
                pos++;
            }
        }

        private void expect(String literal) {
            if (!text.startsWith(literal, pos)) {
                throw error("Expected '" + literal + "'");
            }
            pos += literal.length();
        }

        private static boolean isDigit(char c) {
            return c >= '0' && c <= '9';
        }

        private static int hexValue(char c) {
            if (c >= '0' && c <= '9') {
                return c - '0';
            }
            if (c >= 'a' && c <= 'f') {
                return c - 'a' + 10;
            }
            if (c >= 'A' && c <= 'F') {
                return c - 'A' + 10;
            }
            return -1;
        }

        private static String hex4(char c) {
            char[] digits = new char[4];
            digits[0] = HEX[(c >> 12) & 0xF];
            digits[1] = HEX[(c >> 8) & 0xF];
            digits[2] = HEX[(c >> 4) & 0xF];
            digits[3] = HEX[c & 0xF];
            return new String(digits);
        }
    }
}
