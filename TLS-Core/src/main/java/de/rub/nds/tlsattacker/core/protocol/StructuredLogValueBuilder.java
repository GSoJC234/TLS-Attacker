/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.protocol;

import java.lang.reflect.Array;
import java.util.LinkedHashMap;
import java.util.Map;

/** Builds deterministic, single-line JSON values for protocol trace logging. */
public final class StructuredLogValueBuilder {

    private static final char[] HEX_DIGITS = "0123456789ABCDEF".toCharArray();

    private final Map<String, Object> fields = new LinkedHashMap<>();

    public StructuredLogValueBuilder add(String name, Object value) {
        if (!fields.containsKey(name)) {
            fields.put(name, value);
        }
        return this;
    }

    public StructuredLogValueBuilder addHex(String name, byte[] value) {
        return add(name, value == null ? null : toHex(value));
    }

    public static String toHex(byte[] value) {
        if (value == null) {
            return null;
        }
        StringBuilder builder = new StringBuilder(Math.max(0, value.length * 3 - 1));
        for (int index = 0; index < value.length; index++) {
            if (index > 0) {
                builder.append(' ');
            }
            int unsigned = value[index] & 0xFF;
            builder.append(HEX_DIGITS[unsigned >>> 4]).append(HEX_DIGITS[unsigned & 0x0F]);
        }
        return builder.toString();
    }

    @Override
    public String toString() {
        StringBuilder builder = new StringBuilder();
        appendTo(builder);
        return builder.toString();
    }

    private void appendTo(StringBuilder builder) {
        appendJson(builder, fields);
    }

    private static void appendJson(StringBuilder builder, Object value) {
        if (value == null) {
            builder.append("null");
        } else if (value instanceof StructuredLogValueBuilder) {
            ((StructuredLogValueBuilder) value).appendTo(builder);
        } else if (value instanceof Enum<?>) {
            appendQuoted(builder, ((Enum<?>) value).name());
        } else if (value instanceof Number || value instanceof Boolean) {
            builder.append(value);
        } else if (value instanceof String) {
            appendQuoted(builder, (String) value);
        } else if (value instanceof Map<?, ?>) {
            appendMap(builder, (Map<?, ?>) value);
        } else if (value instanceof Iterable<?>) {
            appendIterable(builder, (Iterable<?>) value);
        } else if (value.getClass().isArray()) {
            appendArray(builder, value);
        } else {
            throw new IllegalArgumentException(
                    "Unsupported structured log value type: " + value.getClass().getName());
        }
    }

    private static void appendMap(StringBuilder builder, Map<?, ?> values) {
        builder.append('{');
        boolean first = true;
        for (Map.Entry<?, ?> entry : values.entrySet()) {
            if (!first) {
                builder.append(',');
            }
            first = false;
            if (!(entry.getKey() instanceof String)) {
                throw new IllegalArgumentException("Structured log map keys must be strings");
            }
            appendQuoted(builder, (String) entry.getKey());
            builder.append(':');
            appendJson(builder, entry.getValue());
        }
        builder.append('}');
    }

    private static void appendIterable(StringBuilder builder, Iterable<?> values) {
        builder.append('[');
        boolean first = true;
        for (Object value : values) {
            if (!first) {
                builder.append(',');
            }
            first = false;
            appendJson(builder, value);
        }
        builder.append(']');
    }

    private static void appendArray(StringBuilder builder, Object values) {
        if (values instanceof byte[]) {
            appendQuoted(builder, toHex((byte[]) values));
            return;
        }
        builder.append('[');
        for (int index = 0; index < Array.getLength(values); index++) {
            if (index > 0) {
                builder.append(',');
            }
            appendJson(builder, Array.get(values, index));
        }
        builder.append(']');
    }

    private static void appendQuoted(StringBuilder builder, String value) {
        builder.append('"');
        for (int index = 0; index < value.length(); index++) {
            char character = value.charAt(index);
            switch (character) {
                case '"':
                    builder.append("\\\"");
                    break;
                case '\\':
                    builder.append("\\\\");
                    break;
                case '\b':
                    builder.append("\\b");
                    break;
                case '\f':
                    builder.append("\\f");
                    break;
                case '\n':
                    builder.append("\\n");
                    break;
                case '\r':
                    builder.append("\\r");
                    break;
                case '\t':
                    builder.append("\\t");
                    break;
                default:
                    if (character < 0x20) {
                        builder.append(String.format("\\u%04X", (int) character));
                    } else {
                        builder.append(character);
                    }
            }
        }
        builder.append('"');
    }
}
