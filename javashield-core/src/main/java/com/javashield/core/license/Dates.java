package com.javashield.core.license;

import java.time.Instant;
import java.time.LocalDate;
import java.time.ZoneOffset;
import java.time.format.DateTimeParseException;

/** Small date helpers shared by the licence, the manifest and the agent. */
public final class Dates {

    private Dates() {
    }

    /**
     * Parses {@code yyyy-MM-dd}, {@code yyyy-MM-ddTHH:mm:ss} or an ISO instant.
     *
     * @return the date in UTC, or {@code null} when the text is blank
     * @throws IllegalArgumentException when the text cannot be parsed
     */
    public static LocalDate parseDate(String text) {
        if (text == null || text.trim().isEmpty()) {
            return null;
        }
        String value = text.trim();
        try {
            if (value.length() >= 20 && value.charAt(10) == 'T') {
                return Instant.parse(value).atZone(ZoneOffset.UTC).toLocalDate();
            }
            if (value.length() > 10 && value.charAt(10) == 'T') {
                return LocalDate.parse(value.substring(0, 10));
            }
            return LocalDate.parse(value);
        } catch (DateTimeParseException exc) {
            throw new IllegalArgumentException("invalid date: " + text, exc);
        }
    }

    public static String today() {
        return LocalDate.now(ZoneOffset.UTC).toString();
    }

    public static String now() {
        return Instant.now().toString();
    }
}
