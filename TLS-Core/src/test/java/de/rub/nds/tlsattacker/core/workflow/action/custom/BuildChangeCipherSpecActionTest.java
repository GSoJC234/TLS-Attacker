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

import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.connection.OutboundConnection;
import de.rub.nds.tlsattacker.core.constants.ProtocolMessageType;
import de.rub.nds.tlsattacker.core.constants.ProtocolVersion;
import de.rub.nds.tlsattacker.core.constants.RunningModeType;
import de.rub.nds.tlsattacker.core.protocol.ProtocolMessage;
import de.rub.nds.tlsattacker.core.protocol.message.ChangeCipherSpecMessage;
import de.rub.nds.tlsattacker.core.record.Record;
import de.rub.nds.tlsattacker.core.state.State;
import de.rub.nds.tlsattacker.core.workflow.WorkflowTrace;
import java.util.ArrayList;
import java.util.List;
import org.junit.jupiter.api.Test;

public class BuildChangeCipherSpecActionTest {

    private static final String CONNECTION_ALIAS = "client";

    @Test
    public void defaultsToTheValidCcsByte() {
        assertCcsBytes(null, (byte) 0x01);
    }

    @Test
    public void explicitTrueUsesTheValidCcsByte() {
        assertCcsBytes(true, (byte) 0x01);
    }

    @Test
    public void falseUsesAOneByteZeroPayload() {
        assertCcsBytes(false, (byte) 0x00);
    }

    private void assertCcsBytes(Boolean valid, byte expectedByte) {
        List<ProtocolMessage> messages = new ArrayList<>();
        BuildChangeCipherSpecAction build =
                new BuildChangeCipherSpecAction(CONNECTION_ALIAS, messages);
        if (valid != null) {
            build.setCcsProtocolTypeValid(valid);
        }
        build.execute(new State());

        ChangeCipherSpecMessage message =
                assertInstanceOf(ChangeCipherSpecMessage.class, messages.get(0));
        assertArrayEquals(new byte[] {expectedByte}, message.getCcsProtocolType().getValue());
        assertArrayEquals(
                new byte[] {expectedByte}, message.getCompleteResultingMessage().getValue());

        List<Record> records = new ArrayList<>();
        BuildRecordAction recordBuilder = new BuildRecordAction(CONNECTION_ALIAS, records);
        recordBuilder.setProtocolMessage(messages);
        recordBuilder.setProtocolMessageType(List.of(ProtocolMessageType.CHANGE_CIPHER_SPEC));
        recordBuilder.setProtocolVersion(List.of(ProtocolVersion.TLS12));
        recordBuilder.execute(clientState());

        assertArrayEquals(
                new byte[] {0x14, 0x03, 0x03, 0x00, 0x01, expectedByte},
                records.get(0).getCompleteRecordBytes().getValue());
    }

    private State clientState() {
        Config config = Config.createConfig();
        config.setDefaultRunningMode(RunningModeType.CLIENT);
        WorkflowTrace trace = new WorkflowTrace();
        trace.addConnection(new OutboundConnection(CONNECTION_ALIAS));
        return new State(config, trace);
    }
}
