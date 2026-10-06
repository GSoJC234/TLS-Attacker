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
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;

import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.connection.AliasedConnection;
import de.rub.nds.tlsattacker.core.connection.OutboundConnection;
import de.rub.nds.tlsattacker.core.constants.HandshakeMessageType;
import de.rub.nds.tlsattacker.core.constants.ProtocolVersion;
import de.rub.nds.tlsattacker.core.constants.RunningModeType;
import de.rub.nds.tlsattacker.core.exceptions.ActionExecutionException;
import de.rub.nds.tlsattacker.core.protocol.ProtocolMessage;
import de.rub.nds.tlsattacker.core.protocol.message.CertificateMessage;
import de.rub.nds.tlsattacker.core.protocol.message.cert.CertificateEntry;
import de.rub.nds.tlsattacker.core.state.State;
import de.rub.nds.tlsattacker.core.workflow.WorkflowTrace;
import de.rub.nds.tlsattacker.core.workflow.action.custom.BuildCertificateAction;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import org.junit.jupiter.api.Test;

public class AddCertificateEntryStatusRequestExtensionActionTest {

    private static final String ALIAS = AliasedConnection.DEFAULT_CONNECTION_ALIAS;

    @Test
    public void addsOcspResponseInsideSelectedCertificateEntry() throws Exception {
        State state = clientState(ProtocolVersion.TLS13);
        List<ProtocolMessage> messages = buildCertificate(state);

        AddCertificateEntryStatusRequestExtensionAction action =
                new AddCertificateEntryStatusRequestExtensionAction(ALIAS, messages);
        action.setCertificateEntryIndex(0);
        action.setOcspResponse(new byte[] {0x30, 0x00});
        action.execute(state);

        CertificateMessage certificate = (CertificateMessage) messages.get(0);
        CertificateEntry entry = certificate.getCertificateEntryList().get(0);
        byte[] expectedExtension = {0, 5, 0, 6, 1, 0, 0, 2, 0x30, 0};
        assertArrayEquals(expectedExtension, entry.getExtensionBytes().getValue());
        assertEquals(expectedExtension.length, entry.getExtensionsLength().getValue());
        assertEquals(3 + 1 + 2 + expectedExtension.length,
                certificate.getCertificatesListLength().getValue());

        byte[] wire = certificate.getCompleteResultingMessage().getValue();
        assertArrayEquals(expectedExtension,
                Arrays.copyOfRange(wire, wire.length - expectedExtension.length, wire.length));
        assertEquals(wire.length - 4, certificate.getLength().getValue());
    }

    @Test
    public void rejectsOutOfRangeEntryWithoutChangingCertificate() throws Exception {
        State state = clientState(ProtocolVersion.TLS13);
        List<ProtocolMessage> messages = buildCertificate(state);
        AddCertificateEntryStatusRequestExtensionAction action =
                new AddCertificateEntryStatusRequestExtensionAction(ALIAS, messages);
        action.setCertificateEntryIndex(1);
        action.setOcspResponse(new byte[] {0x30, 0x00});

        assertThrows(ActionExecutionException.class, () -> action.execute(state));
        CertificateMessage certificate = (CertificateMessage) messages.get(0);
        assertNull(certificate.getCertificateEntryList().get(0).getExtensionList());
    }

    @Test
    public void rejectsEmptyOcspResponse() {
        assertThrows(IllegalArgumentException.class,
                () -> AddCertificateEntryStatusRequestExtensionAction
                        .encodeCertificateStatus(new byte[0]));
    }

    private static State clientState(ProtocolVersion version) {
        Config config = Config.createConfig();
        config.setDefaultRunningMode(RunningModeType.CLIENT);
        config.setDefaultSelectedProtocolVersion(version);
        WorkflowTrace trace = new WorkflowTrace();
        trace.addConnection(new OutboundConnection(ALIAS));
        State state = new State(config, trace);
        state.getTlsContext(ALIAS).setSelectedProtocolVersion(version);
        return state;
    }

    private static List<ProtocolMessage> buildCertificate(State state) throws Exception {
        List<ProtocolMessage> messages = new ArrayList<>();
        BuildCertificateAction action = new BuildCertificateAction(ALIAS, messages);
        action.setHandshakeType(List.of(HandshakeMessageType.CERTIFICATE));
        action.setCertificate(List.of(new CertificateEntry(new byte[] {1})));
        action.setCertificateRequestContext(List.of(new byte[0]));
        action.setCertificateRequestContextLen(List.of(0));
        action.execute(state);
        return messages;
    }
}
