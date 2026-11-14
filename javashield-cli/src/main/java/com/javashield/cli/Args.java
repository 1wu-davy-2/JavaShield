package com.javashield.cli;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/** Very small option parser: {@code --key value}, {@code --key=value}, {@code -k value}. */
public final class Args {

    private final Map<String, List<String>> values = new LinkedHashMap<String, List<String>>();
    private final List<String> positional = new ArrayList<String>();

    public static Args parse(String[] argv) {
        Args args = new Args();
        for (int i = 0; i < argv.length; i++) {
            String token = argv[i];
            if (token.startsWith("--")) {
                String key = token.substring(2);
                String value = "true";
                int equals = key.indexOf('=');
                if (equals >= 0) {
                    value = key.substring(equals + 1);
                    key = key.substring(0, equals);
                } else if (i + 1 < argv.length && !argv[i + 1].startsWith("-")) {
                    value = argv[++i];
                }
                args.add(key, value);
            } else if (token.startsWith("-") && token.length() == 2) {
                String key = token.substring(1);
                String value = "true";
                if (i + 1 < argv.length && !argv[i + 1].startsWith("-")) {
                    value = argv[++i];
                }
                args.add(key, value);
            } else {
                args.positional.add(token);
            }
        }
        return args;
    }

    private void add(String key, String value) {
        List<String> list = values.get(key);
        if (list == null) {
            list = new ArrayList<String>();
            values.put(key, list);
        }
        list.add(value);
    }

    public boolean has(String name) {
        return values.containsKey(name);
    }

    public String get(String name, String fallback) {
        List<String> list = values.get(name);
        return list == null || list.isEmpty() ? fallback : list.get(list.size() - 1);
    }

    public String required(String name) {
        String value = get(name, null);
        if (value == null || value.trim().isEmpty()) {
            throw new IllegalArgumentException("missing required option --" + name);
        }
        return value;
    }

    /** Returns the first option that is present, or {@code null}. */
    public String first(String... names) {
        for (String name : names) {
            if (values.containsKey(name)) {
                return get(name, null);
            }
        }
        return null;
    }

    public String firstRequired(String... names) {
        String value = first(names);
        if (value == null || value.trim().isEmpty()) {
            StringBuilder joined = new StringBuilder();
            for (String name : names) {
                if (joined.length() > 0) {
                    joined.append('/');
                }
                joined.append("--").append(name);
            }
            throw new IllegalArgumentException("missing required option " + joined);
        }
        return value;
    }

    public boolean flag(String name) {
        List<String> list = values.get(name);
        if (list == null || list.isEmpty()) {
            return false;
        }
        return !"false".equalsIgnoreCase(list.get(list.size() - 1));
    }

    public int intValue(String name, int fallback) {
        String value = get(name, null);
        if (value == null || value.trim().isEmpty()) {
            return fallback;
        }
        try {
            return Integer.parseInt(value.trim());
        } catch (NumberFormatException exc) {
            throw new IllegalArgumentException("--" + name + " must be a number: " + value);
        }
    }

    public List<String> all(String name) {
        List<String> list = values.get(name);
        return list == null ? new ArrayList<String>() : new ArrayList<String>(list);
    }

    public List<String> positional() {
        return new ArrayList<String>(positional);
    }
}
