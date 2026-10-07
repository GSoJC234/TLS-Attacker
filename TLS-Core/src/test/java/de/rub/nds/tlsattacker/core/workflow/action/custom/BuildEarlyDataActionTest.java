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
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.connection.AliasedConnection;
import de.rub.nds.tlsattacker.core.connection.OutboundConnection;
import de.rub.nds.tlsattacker.core.constants.ExtensionType;
import de.rub.nds.tlsattacker.core.constants.RunningModeType;
import de.rub.nds.tlsattacker.core.constants.Tls13KeySetType;
import de.rub.nds.tlsattacker.core.exceptions.ActionExecutionException;
import de.rub.nds.tlsattacker.core.protocol.ProtocolMessage;
import de.rub.nds.tlsattacker.core.protocol.message.ApplicationMessage;
import de.rub.nds.tlsattacker.core.state.State;
import de.rub.nds.tlsattacker.core.workflow.WorkflowTrace;
import java.util.ArrayList;
import java.util.List;
import org.junit.jupiter.api.Test;

public class BuildEarlyDataActionTest {

    private static final String CONNECTION_ALIAS = "client";

    @Test
    public void buildsEarlyDataOnlyAfterEarlyTrafficKeysAreActive() {
        byte[] payload = new byte[] {0x01, 0x23, (byte) 0xFF};
        State state = clientState();
        var tlsContext = state.getTlsContext(CONNECTION_ALIAS);
        tlsContext.addProposedExtension(ExtensionType.EARLY_DATA);
        tlsContext.setClientEarlyTrafficSecret(new byte[] {0x01});
        tlsContext.setActiveClientKeySetType(Tls13KeySetType.EARLY_TRAFFIC_SECRETS);

        List<ProtocolMessage> messages = new ArrayList<>();
        BuildEarlyDataAction action = new BuildEarlyDataAction(CONNECTION_ALIAS, messages);
        action.setPayload(List.of(payload));

        action.execute(state);

        ApplicationMessage message = assertInstanceOf(ApplicationMessage.class, messages.get(0));
        assertArrayEquals(payload, message.getDataConfig());
        assertArrayEquals(payload, message.getData().getValue());
        assertTrue(action.executedAsPlanned());
    }

    @Test
    public void rejectsEarlyDataWithoutEarlyDataExtension() {
        State state = clientState();
        BuildEarlyDataAction action =
                new BuildEarlyDataAction(CONNECTION_ALIAS, new ArrayList<>());
        action.setPayload(List.of(new byte[] {0x01}));

        assertThrows(ActionExecutionException.class, () -> action.execute(state));
    }

    @Test
    public void rejectsEarlyDataBeforeEarlyWriteKeysAreActive() {
        State state = clientState();
        state.getTlsContext(CONNECTION_ALIAS).addProposedExtension(ExtensionType.EARLY_DATA);
        BuildEarlyDataAction action =
                new BuildEarlyDataAction(CONNECTION_ALIAS, new ArrayList<>());
        action.setPayload(List.of(new byte[] {0x01}));

        assertThrows(ActionExecutionException.class, () -> action.execute(state));
    }

    private State clientState() {
        Config config = Config.createConfig();
        config.setDefaultRunningMode(RunningModeType.CLIENT);
        WorkflowTrace trace = new WorkflowTrace();
        trace.addConnection(new OutboundConnection(CONNECTION_ALIAS));
        return new State(config, trace);
    }
}
