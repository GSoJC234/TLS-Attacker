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
import static org.junit.jupiter.api.Assertions.assertEquals;

import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.connection.AliasedConnection;
import de.rub.nds.tlsattacker.core.connection.InboundConnection;
import de.rub.nds.tlsattacker.core.constants.ProtocolVersion;
import de.rub.nds.tlsattacker.core.constants.RunningModeType;
import de.rub.nds.tlsattacker.core.protocol.ProtocolMessage;
import de.rub.nds.tlsattacker.core.protocol.message.NewSessionTicketMessage;
import de.rub.nds.tlsattacker.core.state.SessionTicket;
import de.rub.nds.tlsattacker.core.state.State;
import de.rub.nds.tlsattacker.core.workflow.WorkflowTrace;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import org.junit.jupiter.api.Test;

public class BuildNewSessionTicketTest {

    @Test
    public void serializesTheSameNormalizedNonceUsedForResumptionPskDerivation() {
        byte[] nonce = new byte[32];
        for (int i = 0; i < nonce.length; i++) {
            nonce[i] = (byte) i;
        }

        SessionTicket ticket = new SessionTicket();
        ticket.setTicketNonce(nonce);
        ticket.setTicketNonceLength(nonce.length);
        ticket.setIdentity(new byte[] {1, 2, 3, 4});
        ticket.setIdentityLength(4);
        ticket.setTicketAgeAdd(new byte[] {5, 6, 7, 8});

        List<ProtocolMessage> messages = new ArrayList<>();
        BuildNewSessionTicket action =
                new BuildNewSessionTicket(AliasedConnection.DEFAULT_CONNECTION_ALIAS, messages);
        action.setTicket(List.of(ticket));
        action.execute(stateFor(ProtocolVersion.TLS13));

        NewSessionTicketMessage result = (NewSessionTicketMessage) messages.get(0);
        byte[] expected = new byte[] {0, 1, 2, 3, 4, 5, 6, 7};
        assertArrayEquals(expected, BuildNewSessionTicket.serializedTicketNonce(ticket));
        assertArrayEquals(expected, result.getTicket().getTicketNonce().getValue());
    }

    @Test
    public void serializesOversizedTicketUsingTls12WireFormat() {
        byte[] identity = new byte[257];
        for (int i = 0; i < identity.length; i++) {
            identity[i] = (byte) i;
        }

        SessionTicket ticket = new SessionTicket();
        ticket.setIdentity(identity);
        ticket.setIdentityLength(identity.length);

        List<ProtocolMessage> messages = new ArrayList<>();
        BuildNewSessionTicket action =
                new BuildNewSessionTicket(AliasedConnection.DEFAULT_CONNECTION_ALIAS, messages);
        action.setTicket(List.of(ticket));
        action.execute(stateFor(ProtocolVersion.TLS12));

        NewSessionTicketMessage result = (NewSessionTicketMessage) messages.get(0);
        byte[] body = result.getMessageContent().getValue();
        byte[] wire = result.getCompleteResultingMessage().getValue();

        assertEquals(4 + 2 + identity.length, body.length);
        assertEquals(identity.length, ((body[4] & 0xff) << 8) | (body[5] & 0xff));
        assertArrayEquals(identity, Arrays.copyOfRange(body, 6, body.length));
        assertEquals(body.length + 4, wire.length);
        assertEquals(body.length, result.getLength().getValue());
    }

    private State stateFor(ProtocolVersion protocolVersion) {
        Config config = Config.createConfig();
        config.setDefaultRunningMode(RunningModeType.SERVER);
        config.setDefaultSelectedProtocolVersion(protocolVersion);
        WorkflowTrace trace = new WorkflowTrace();
        trace.addConnection(new InboundConnection(AliasedConnection.DEFAULT_CONNECTION_ALIAS));
        State state = new State(config, trace);
        state.getTlsContext(AliasedConnection.DEFAULT_CONNECTION_ALIAS)
                .setSelectedProtocolVersion(protocolVersion);
        return state;
    }
}
