package com.javashield.core.json;

import org.junit.jupiter.api.Test;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

class JsonTest {

    // 1. 嵌套对象/数组解析后 canonical 往返一致 -------------------------------------

    @Test
    void nestedStructuresRoundTripThroughCanonical() {
        String text = "{\"license\":{\"subject\":\"acme\",\"features\":[\"debug\",\"trace\"],"
                + "\"limits\":{\"seats\":10,\"expires\":1893456000000}},"
                + "\"version\":1,\"signed\":true,\"revoked\":null}";

        Object parsed = Json.parse(text);
        String canonical = Json.canonical(parsed);

        assertEquals("{\"license\":{\"features\":[\"debug\",\"trace\"],"
                        + "\"limits\":{\"expires\":1893456000000,\"seats\":10},\"subject\":\"acme\"},"
                        + "\"revoked\":null,\"signed\":true,\"version\":1}",
                canonical);
        // canonical 输出必须可以再次解析且结果等价（幂等）。
        assertEquals(canonical, Json.canonical(Json.parse(canonical)));
    }

    @Test
    void parseProducesExpectedJavaTypes() {
        Map<String, Object> object = Json.parseObject(
                "{\"i\":-9223372036854775808,\"d\":1.5e3,\"s\":\"x\",\"b\":false,\"n\":null}");

        assertEquals(Long.valueOf(-9223372036854775808L), object.get("i"));
        assertEquals(Double.valueOf(1500.0d), object.get("d"));
        assertEquals("x", object.get("s"));
        assertEquals(Boolean.FALSE, object.get("b"));
        assertNull(object.get("n"));
        assertTrue(object instanceof LinkedHashMap);
        assertTrue(Json.parse("[]") instanceof ArrayList);
    }

    @Test
    void duplicateKeysLastOneWins() {
        assertEquals("{\"a\":2}", Json.canonical(Json.parse("{\"a\":1,\"a\":2}")));
    }

    @Test
    void integerLiteralBeyondLongRangeDegradesToDouble() {
        Object value = Json.parse("9223372036854775808");
        assertTrue(value instanceof Double);
        assertEquals("9.223372036854776E18", Json.canonical(value));
    }

    // 2. 键排序 -------------------------------------------------------------------

    @Test
    void canonicalSortsKeysWithStringCompareTo() {
        assertEquals("{\"a\":2,\"b\":1}",
                Json.canonical(Json.parse("{\"b\":1,\"a\":2}")));

        assertEquals("{\"A\":1,\"Z\":2,\"a\":3,\"z\":4}",
                Json.canonical(Json.parse("{\"z\":4,\"a\":3,\"Z\":2,\"A\":1}")));

        // 排序发生在每一层，而不只是顶层。
        assertEquals("{\"outer\":{\"x\":1,\"y\":2}}",
                Json.canonical(Json.parse("{\"outer\":{\"y\":2,\"x\":1}}")));
    }

    // 3. 非 ASCII 一律转义为小写十六进制 ----------------------------------------------

    @Test
    void chineseAndEmojiAreEscapedAsLowercaseHex() {
        String canonical = Json.canonical(Json.parse("{\"名字\":\"张三😀\"}"));

        assertEquals("{\"\\u540d\\u5b57\":\"\\u5f20\\u4e09\\ud83d\\ude00\"}", canonical);
        // 转义后的文本必须能被还原成原始 UTF-16 字符串（含代理对）。
        assertEquals("张三😀", Json.asString(Json.parseObject(canonical).get("名字")));
        // 输出必须是纯 ASCII。
        for (int i = 0; i < canonical.length(); i++) {
            assertTrue(canonical.charAt(i) < 0x7F, "non-ASCII character leaked at index " + i);
        }
    }

    @Test
    void boundaryCharactersAreEscaped() {
        assertEquals("\"~\\u007f\\u0080\\u00e9\"",
                Json.canonical(Json.parse("\"~\\u007f\\u0080\\u00e9\"")));
    }

    // 4. 控制字符、引号、反斜杠 ------------------------------------------------------

    @Test
    void controlQuotesAndBackslashesUseShortEscapes() {
        // 原始字符串：双引号、反斜杠、退格、换页、换行、回车、制表符、U+0001
        String raw = "\"\\\b\f\n\r\t\u0001";

        assertEquals("\"\\\"\\\\\\b\\f\\n\\r\\t\\u0001\"", Json.canonical(raw));

        // 解析上面 canonical 文本，必须逐字符还原原始字符串，并且再次序列化结果相同。
        Object reparsed = Json.parse(Json.canonical(raw));
        assertEquals(raw, Json.asString(reparsed));
        assertEquals(Json.canonical(raw), Json.canonical(reparsed));
    }

    @Test
    void slashEscapeIsAcceptedButNotEmitted() {
        assertEquals("\"a/b\"", Json.canonical("a/b"));
        assertEquals("/a/b", Json.asString(Json.parse("\"\\/a\\/b\"")));
    }

    // 5. 空对象与空数组 ------------------------------------------------------------

    @Test
    void emptyContainersRenderAsBracesAndBrackets() {
        assertEquals("{}", Json.canonical(Json.parse("{}")));
        assertEquals("[]", Json.canonical(Json.parse("[]")));
        assertEquals("{\"a\":{},\"b\":[]}",
                Json.canonical(Json.parse("{ \"a\" : { } , \"b\" : [ ] }")));
        assertEquals("{}", Json.pretty(Json.parse("{}")));
        assertEquals("[]", Json.pretty(Json.parse("[]")));
    }

    // 6. 非法输入 -----------------------------------------------------------------

    @Test
    void invalidDocumentsThrowIllegalArgumentException() {
        String[] invalid = {
                "",                       // 空输入
                "   ",                    // 只有空白
                "{\"a\":1",               // 截断的对象
                "{\"a\":}",               // 缺少值
                "{\"a\" 1}",              // 缺少冒号
                "{\"a\":1,}",             // 尾随逗号
                "[1,2",                   // 截断的数组
                "[1,]",                   // 数组尾随逗号
                "{} {}",                  // 多余尾随内容
                "1 2",                    // 数字后有多余内容
                "tru",                    // 不完整的字面量
                "\"abc",                  // 未闭合的字符串
                "\"\\q\"",                // 非法转义
                "\"\\u12g4\"",            // 非法十六进制
                "\"a\nb\"",               // 未转义的控制字符
                ".5",                     // 非法数字
                "01",                     // 前导零
                "1.",                     // 小数点后无数字
                "1e",                     // 指数缺数字
                "-",                      // 只有符号
                "{a:1}"                   // 键未加引号
        };
        for (String text : invalid) {
            IllegalArgumentException error = assertThrows(IllegalArgumentException.class,
                    () -> Json.parse(text), "expected rejection of: " + text);
            assertTrue(error.getMessage() != null && error.getMessage().contains("index"),
                    "error message should mention a character index: " + error.getMessage());
        }
    }

    @Test
    void errorMessageReportsPosition() {
        IllegalArgumentException error = assertThrows(IllegalArgumentException.class,
                () -> Json.parse("{\"a\":1}x"));
        assertTrue(error.getMessage().contains("index 7"), error.getMessage());
    }

    // 7. parseObject 类型校验 -------------------------------------------------------

    @Test
    void parseObjectRejectsNonObjectDocuments() {
        assertThrows(IllegalArgumentException.class, () -> Json.parseObject("[1,2]"));
        assertThrows(IllegalArgumentException.class, () -> Json.parseObject("\"text\""));
        assertThrows(IllegalArgumentException.class, () -> Json.parseObject("null"));
    }

    // 8. pretty 输出可解析且 canonical 一致 -----------------------------------------

    @Test
    void prettyOutputIsParseableAndCanonicallyEqual() {
        String text = "{\"b\":[1,2,{\"d\":true,\"c\":null}],\"a\":\"中文\",\"e\":{}}";
        Object original = Json.parse(text);

        String pretty = Json.pretty(original);
        assertEquals("{\n"
                + "  \"a\": \"\\u4e2d\\u6587\",\n"
                + "  \"b\": [\n"
                + "    1,\n"
                + "    2,\n"
                + "    {\n"
                + "      \"c\": null,\n"
                + "      \"d\": true\n"
                + "    }\n"
                + "  ],\n"
                + "  \"e\": {}\n"
                + "}", pretty);
        assertEquals(Json.canonical(original), Json.canonical(Json.parse(pretty)));
    }

    // 便捷方法 ---------------------------------------------------------------------

    @Test
    void accessorsCoerceWhereDocumentedAndRejectOtherwise() {
        assertEquals("v", Json.asString("v"));
        assertThrows(IllegalArgumentException.class, () -> Json.asString(null));
        assertThrows(IllegalArgumentException.class, () -> Json.asString(Long.valueOf(1)));

        assertEquals(42L, Json.asLong(Long.valueOf(42)));
        assertEquals(42L, Json.asLong(Integer.valueOf(42)));
        assertEquals(42L, Json.asLong("42"));
        assertThrows(IllegalArgumentException.class, () -> Json.asLong("4x"));
        assertThrows(IllegalArgumentException.class, () -> Json.asLong(Double.valueOf(4.0d)));

        assertTrue(Json.asBoolean(Boolean.TRUE));
        assertThrows(IllegalArgumentException.class, () -> Json.asBoolean("true"));
    }

    // 序列化的数据类型边界 ---------------------------------------------------------

    @Test
    void serializationRejectsUnsupportedTypes() {
        assertThrows(IllegalArgumentException.class, () -> Json.canonical(new Object()));
        assertThrows(IllegalArgumentException.class, () -> Json.canonical(new byte[]{1, 2}));
        assertThrows(IllegalArgumentException.class, () -> Json.pretty(new int[]{1}));

        Map<Object, Object> badKey = new LinkedHashMap<Object, Object>();
        badKey.put(Integer.valueOf(1), "x");
        assertThrows(IllegalArgumentException.class, () -> Json.canonical(badKey));
    }

    @Test
    void longAndDoubleSerializationUsesToString() {
        assertEquals("{\"big\":9223372036854775807,\"small\":-1}",
                Json.canonical(map("small", -1L, "big", 9223372036854775807L)));
        assertEquals("1.5", Json.canonical(Double.valueOf(1.5d)));
        assertEquals("1.0E10", Json.canonical(Double.valueOf(1.0E10d)));
        assertEquals("null", Json.canonical(null));
    }

    // 辅助 -------------------------------------------------------------------------

    private static Map<String, Object> map(Object... keyValues) {
        Map<String, Object> map = new LinkedHashMap<String, Object>();
        for (int i = 0; i < keyValues.length; i += 2) {
            map.put((String) keyValues[i], keyValues[i + 1]);
        }
        return map;
    }

    @Test
    void helperMapRoundTrips() {
        List<Object> list = new ArrayList<Object>();
        list.add(Long.valueOf(1));
        list.add("x");
        Map<String, Object> value = map("z", list, "a", Boolean.TRUE);
        assertEquals("{\"a\":true,\"z\":[1,\"x\"]}", Json.canonical(value));
    }
}
