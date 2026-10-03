/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.workflow.observation;

import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import org.junit.jupiter.api.Test;

public class ExecutionEventEmitterTest {

    @Test
    public void formatsSingleLineKeyValueEvent() {
        String event = ExecutionEventEmitter.format(
                "TESTER", "SERVER_READY", "connectionId", "N2 . SI", "port", 4433);

        assertTrue(event.startsWith("MTA_EVENT eventSeq="));
        assertTrue(!event.contains(" runId="));
        assertTrue(event.contains(" actor=TESTER type=SERVER_READY"));
        assertTrue(event.contains(" connectionId=N2%20.%20SI"));
        assertTrue(event.contains(" port=4433"));
        assertTrue(!event.contains("\n"));
    }

    @Test
    public void rejectsUnpairedFields() {
        assertThrows(
                IllegalArgumentException.class,
                () -> ExecutionEventEmitter.format("TESTER", "SERVER_READY", "port"));
    }
}
