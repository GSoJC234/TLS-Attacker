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
import static org.junit.jupiter.api.Assertions.assertInstanceOf;

import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.connection.AliasedConnection;
import de.rub.nds.tlsattacker.core.connection.InboundConnection;
import de.rub.nds.tlsattacker.core.constants.CipherSuite;
import de.rub.nds.tlsattacker.core.constants.CompressionMethod;
import de.rub.nds.tlsattacker.core.constants.HandshakeMessageType;
import de.rub.nds.tlsattacker.core.constants.ProtocolVersion;
import de.rub.nds.tlsattacker.core.constants.RunningModeType;
import de.rub.nds.tlsattacker.core.layer.context.TlsContext;
import de.rub.nds.tlsattacker.core.protocol.ProtocolMessage;
import de.rub.nds.tlsattacker.core.protocol.message.ClientHelloMessage;
import de.rub.nds.tlsattacker.core.state.State;
import de.rub.nds.tlsattacker.core.workflow.WorkflowTrace;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import org.junit.jupiter.api.Test;

public class BuildWrongSideClientHelloActionTest {

    @Test
    public void buildsStructurallyValidClientHelloFromServerHelloContext() {
        Config config = Config.createConfig();
        config.setDefaultRunningMode(RunningModeType.SERVER);
        WorkflowTrace trace = new WorkflowTrace();
        trace.addConnection(new InboundConnection(AliasedConnection.DEFAULT_CONNECTION_ALIAS));
        State state = new State(config, trace);
        TlsContext tlsContext =
                state.getTlsContext(AliasedConnection.DEFAULT_CONNECTION_ALIAS);
        byte[] serverRandom = new byte[32];
        for (int index = 0; index < serverRandom.length; index++) {
            serverRandom[index] = (byte) index;
        }
        tlsContext.setSelectedProtocolVersion(ProtocolVersion.TLS12);
        tlsContext.setSelectedCipherSuite(
                CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256);
        tlsContext.setServerRandom(serverRandom);
        tlsContext.setSelectedCompressionMethod(CompressionMethod.NULL);

        List<ProtocolMessage> output = new ArrayList<>();
        BuildWrongSideClientHelloAction action =
                new BuildWrongSideClientHelloAction(
                        AliasedConnection.DEFAULT_CONNECTION_ALIAS, output);
        action.setHandshakeType(List.of(HandshakeMessageType.CLIENT_HELLO));
        action.execute(state);

        ClientHelloMessage message =
                assertInstanceOf(ClientHelloMessage.class, output.get(0));
        byte[] wire = message.getCompleteResultingMessage().getValue();
        int declaredHandshakeLength =
                ((wire[1] & 0xff) << 16) | ((wire[2] & 0xff) << 8) | (wire[3] & 0xff);

        assertEquals(HandshakeMessageType.CLIENT_HELLO.getValue(), wire[0]);
        assertEquals(wire.length - 4, declaredHandshakeLength);
        assertEquals(declaredHandshakeLength, message.getLength().getValue());
        assertArrayEquals(ProtocolVersion.TLS12.getValue(), message.getProtocolVersion().getValue());
        assertArrayEquals(serverRandom, Arrays.copyOfRange(wire, 6, 38));
        assertArrayEquals(
                CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256.getByteValue(),
                message.getCipherSuites().getValue());
        assertEquals(2, message.getCipherSuiteLength().getValue());
        assertArrayEquals(
                CompressionMethod.NULL.getArrayValue(), message.getCompressions().getValue());
        assertEquals(1, message.getCompressionLength().getValue());
        assertEquals(
                message.getExtensionBytes().getValue().length,
                message.getExtensionsLength().getValue());
    }
}
