package com.javashield.tool;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;

/** Defensive accessors for values parsed from tool licence and state JSON. */
final class ToolValues {

    private ToolValues() {
    }

    static String string(Object value, String fallback) {
        if (value == null) {
            return fallback;
        }
        return value instanceof String ? (String) value : String.valueOf(value);
    }

    static boolean bool(Object value, boolean fallback) {
        if (value instanceof Boolean) {
            return ((Boolean) value).booleanValue();
        }
        if (value instanceof String) {
            String text = ((String) value).trim();
            if ("true".equalsIgnoreCase(text) || "1".equals(text) || "yes".equalsIgnoreCase(text)) {
                return true;
            }
            if ("false".equalsIgnoreCase(text) || "0".equals(text) || "no".equalsIgnoreCase(text)) {
                return false;
            }
        }
        return fallback;
    }

    static long number(Object value, long fallback) {
        if (value instanceof Number) {
            return ((Number) value).longValue();
        }
        if (value instanceof String) {
            try {
                return Long.parseLong(((String) value).trim());
            } catch (NumberFormatException ignored) {
                return fallback;
            }
        }
        return fallback;
    }

    static int integer(Object value, int fallback) {
        long parsed = number(value, fallback);
        if (parsed > Integer.MAX_VALUE) {
            return Integer.MAX_VALUE;
        }
        if (parsed < Integer.MIN_VALUE) {
            return Integer.MIN_VALUE;
        }
        return (int) parsed;
    }

    static List<String> strings(Object value) {
        List<String> values = new ArrayList<String>();
        if (value instanceof List) {
            for (Object item : (List<?>) value) {
                if (item != null) {
                    values.add(String.valueOf(item));
                }
            }
        } else if (value instanceof String) {
            for (String part : ((String) value).split(",")) {
                if (!part.trim().isEmpty()) {
                    values.add(part.trim());
                }
            }
        }
        return values;
    }

    @SuppressWarnings("unchecked")
    static Map<String, Object> map(Object value) {
        return value instanceof Map ? (Map<String, Object>) value : null;
    }
}
