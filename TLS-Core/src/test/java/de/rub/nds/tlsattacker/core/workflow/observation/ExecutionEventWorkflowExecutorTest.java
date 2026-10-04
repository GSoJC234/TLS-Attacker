/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.workflow.observation;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import de.rub.nds.tlsattacker.core.protocol.message.ApplicationMessage;
import java.security.Security;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.jupiter.api.Test;

public class ExecutionEventWorkflowExecutorTest {

    static {
        Security.addProvider(new BouncyCastleProvider());
    }

    @Test
    public void formatsOneProtocolTraceLineWithSerializedBytesLast() {
        ApplicationMessage message = new ApplicationMessage();
        message.setData(new byte[] {0x01, 0x02});
        message.setCompleteResultingMessage(new byte[] {(byte) 0xDE, (byte) 0xAD});

        String trace =
                ExecutionEventWorkflowExecutor.formatProtocolTrace("SENT", 3, 1, message);

        assertTrue(
                trace.startsWith(
                        "Protocol Message Value: direction=SENT actionIndex=3 messageIndex=1 "
                                + "message=Application value="));
        assertTrue(trace.contains("{\"contentType\":\"APPLICATION_DATA\",\"data\":\"01 02\"}"));
        assertTrue(trace.endsWith(" bytes=DE AD"));
        assertFalse(trace.contains("source="));
        assertFalse(trace.contains("Message Bytes:"));
        assertFalse(trace.contains("\n"));
    }
}
