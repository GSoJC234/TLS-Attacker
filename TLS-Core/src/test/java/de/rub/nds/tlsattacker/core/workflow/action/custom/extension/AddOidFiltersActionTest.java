/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.workflow.action.custom.extension;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import de.rub.nds.tlsattacker.core.protocol.ProtocolMessage;
import de.rub.nds.tlsattacker.core.protocol.message.CertificateRequestMessage;
import de.rub.nds.tlsattacker.core.protocol.message.ClientHelloMessage;
import de.rub.nds.tlsattacker.core.protocol.message.extension.ExtensionMessage;
import de.rub.nds.tlsattacker.transport.ConnectionEndType;
import java.util.List;
import org.junit.jupiter.api.Test;

public class AddOidFiltersActionTest {

    @Test
    public void encodesOidAndDerValueWithNestedTlsLengths() {
        List<ProtocolMessage> messages = List.of(new CertificateRequestMessage());
        AddOidFiltersAction action = new AddOidFiltersAction("connection", messages);
        action.setExtensions(List.of("2.5.29.37"));
        action.setValuesDer(List.of(new byte[] {0x30, 0x00}));

        ExtensionMessage extension =
                action.generateExtensionMessages(ConnectionEndType.SERVER, null);

        assertArrayEquals(
                new byte[] {
                    0x00, 0x30, 0x00, 0x0c,
                    0x00, 0x0a,
                    0x05, 0x06, 0x03, 0x55, 0x1d, 0x25,
                    0x00, 0x02, 0x30, 0x00
                },
                extension.getExtensionBytes().getValue());
    }

    @Test
    public void rejectsMismatchedOidAndValueLists() {
        assertThrows(
                IllegalArgumentException.class,
                () -> AddOidFiltersAction.encodeFilters(List.of("2.5.29.37"), List.of()));
    }

    @Test
    public void rejectsNonCertificateRequestMessages() {
        List<ProtocolMessage> messages = List.of(new ClientHelloMessage());
        AddOidFiltersAction action = new AddOidFiltersAction("connection", messages);
        action.setExtensions(List.of("2.5.29.37"));
        action.setValuesDer(List.of(new byte[] {0x30, 0x00}));

        assertThrows(
                IllegalArgumentException.class,
                () -> action.generateExtensionMessages(ConnectionEndType.SERVER, null));
    }
}
