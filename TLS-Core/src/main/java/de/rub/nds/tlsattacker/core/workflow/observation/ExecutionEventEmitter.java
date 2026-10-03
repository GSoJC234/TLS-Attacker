/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.workflow.observation;

import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.util.concurrent.atomic.AtomicLong;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

/** Emits stable, machine-readable execution events without coupling them to normal debug output. */
public final class ExecutionEventEmitter {

    public static final String LOGGER_NAME = "mta.execution.Event";
    private static final String PREFIX = "MTA_EVENT";
    private static final Logger LOGGER = LogManager.getLogger(LOGGER_NAME);
    private static final AtomicLong SEQUENCE = new AtomicLong();

    private ExecutionEventEmitter() {}

    public static void emit(String actor, String type, Object... fields) {
        LOGGER.info(format(actor, type, fields));
    }

    public static String format(String actor, String type, Object... fields) {
        if (fields.length % 2 != 0) {
            throw new IllegalArgumentException("Execution event fields must be key/value pairs");
        }

        StringBuilder builder = new StringBuilder(PREFIX)
                .append(" eventSeq=").append(SEQUENCE.incrementAndGet())
                .append(" actor=").append(encode(actor))
                .append(" type=").append(encode(type));
        for (int index = 0; index < fields.length; index += 2) {
            builder.append(' ')
                    .append(validateKey(fields[index]))
                    .append('=')
                    .append(encode(fields[index + 1]));
        }
        return builder.toString();
    }

    private static String validateKey(Object rawKey) {
        String key = String.valueOf(rawKey);
        if (!key.matches("[A-Za-z][A-Za-z0-9_]*")) {
            throw new IllegalArgumentException("Invalid execution event field name: " + key);
        }
        return key;
    }

    private static String encode(Object rawValue) {
        String value = rawValue == null ? "null" : String.valueOf(rawValue);
        return URLEncoder.encode(value, StandardCharsets.UTF_8).replace("+", "%20");
    }
}
