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

import de.rub.nds.tlsattacker.core.protocol.ProtocolMessage;
import de.rub.nds.tlsattacker.core.protocol.message.NewSessionTicketMessage;
import de.rub.nds.tlsattacker.core.state.SessionTicket;
import de.rub.nds.tlsattacker.core.state.State;
import java.util.ArrayList;
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
        BuildNewSessionTicket action = new BuildNewSessionTicket("connection", messages);
        action.setTicket(List.of(ticket));
        action.execute(new State());

        NewSessionTicketMessage result = (NewSessionTicketMessage) messages.get(0);
        byte[] expected = new byte[] {0, 1, 2, 3, 4, 5, 6, 7};
        assertArrayEquals(expected, BuildNewSessionTicket.serializedTicketNonce(ticket));
        assertArrayEquals(expected, result.getTicket().getTicketNonce().getValue());
    }
}
