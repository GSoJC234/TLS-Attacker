/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.workflow.action.custom;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertTrue;

import de.rub.nds.tlsattacker.core.protocol.ProtocolMessage;
import de.rub.nds.tlsattacker.core.protocol.message.ApplicationMessage;
import de.rub.nds.tlsattacker.core.state.State;
import java.util.ArrayList;
import java.util.List;
import org.junit.jupiter.api.Test;

public class BuildApplicationDataActionTest {

    @Test
    public void buildsApplicationMessageWithConfiguredPayload() {
        byte[] payload = new byte[] {0x01, 0x23, (byte) 0xFF};
        List<ProtocolMessage> messages = new ArrayList<>();
        BuildApplicationDataAction action =
                new BuildApplicationDataAction("connection", messages);
        action.setPayload(List.of(payload));

        action.execute(new State());

        ApplicationMessage message =
                assertInstanceOf(ApplicationMessage.class, messages.get(0));
        assertArrayEquals(payload, message.getDataConfig());
        assertArrayEquals(payload, message.getData().getValue());
        assertArrayEquals(payload, message.getCompleteResultingMessage().getValue());
        assertTrue(action.executedAsPlanned());
    }
}
