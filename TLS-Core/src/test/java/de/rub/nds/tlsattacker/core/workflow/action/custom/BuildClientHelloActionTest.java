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
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;

import de.rub.nds.tlsattacker.core.constants.CipherSuite;
import de.rub.nds.tlsattacker.core.constants.CompressionMethod;
import de.rub.nds.tlsattacker.core.constants.HandshakeMessageType;
import de.rub.nds.tlsattacker.core.constants.ProtocolVersion;
import de.rub.nds.tlsattacker.core.exceptions.ActionExecutionException;
import de.rub.nds.tlsattacker.core.protocol.ProtocolMessage;
import de.rub.nds.tlsattacker.core.protocol.message.ClientHelloMessage;
import de.rub.nds.tlsattacker.core.state.State;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import org.junit.jupiter.api.Test;

public class BuildClientHelloActionTest {

    private static final int[] SESSION_ID_SIZES = {0, 1, 31, 32, 33, 255};

    @Test
    public void serializesSessionIdPayloadSizesWithMatchingLengthFields() {
        for (int size : SESSION_ID_SIZES) {
            byte[] sessionId = new byte[size];
            for (int index = 0; index < sessionId.length; index++) {
                sessionId[index] = (byte) index;
            }
            ClientHelloMessage message = buildClientHello(sessionId, null);
            byte[] wire = message.getCompleteResultingMessage().getValue();

            assertArrayEquals(sessionId, message.getSessionId().getValue());
            assertEquals(size, message.getSessionIdLength().getValue());
            assertEquals(size, Byte.toUnsignedInt(wire[38]));
            assertArrayEquals(sessionId, Arrays.copyOfRange(wire, 39, 39 + size));
        }
    }

    @Test
    public void buildsClientHelloWithExplicitMismatchedSessionIdLength() {
        byte[] originalSessionId = new byte[32];
        for (int index = 0; index < originalSessionId.length; index++) {
            originalSessionId[index] = (byte) index;
        }

        ClientHelloMessage message = buildClientHello(originalSessionId, 33);
        byte[] wire = message.getCompleteResultingMessage().getValue();

        assertEquals(32, message.getSessionId().getValue().length);
        assertEquals(33, message.getSessionIdLength().getValue());
        assertEquals(33, Byte.toUnsignedInt(wire[38]));
        assertArrayEquals(originalSessionId, Arrays.copyOfRange(wire, 39, 71));
    }

    @Test
    public void rejectsSessionIdLengthFieldsOutsideOneByteRange() {
        byte[] originalSessionId = new byte[32];

        assertThrows(ActionExecutionException.class, () -> buildClientHello(originalSessionId, -1));
        assertThrows(ActionExecutionException.class, () -> buildClientHello(originalSessionId, 256));
    }

    @Test
    public void serializesInvalidCompressionWithoutRecognizingItOnReceive() {
        ClientHelloMessage message = buildClientHelloWithRawCompressions(new byte[] {(byte) 0x7f});
        byte[] wire = message.getCompleteResultingMessage().getValue();

        assertArrayEquals(new byte[] {(byte) 0x7f}, message.getCompressions().getValue());
        assertEquals(1, message.getCompressionLength().getValue());
        assertEquals(1, Byte.toUnsignedInt(wire[43]));
        assertEquals(0x7f, Byte.toUnsignedInt(wire[44]));
        assertNull(CompressionMethod.getCompressionMethod((byte) 0x7f));
    }

    @Test
    public void serializesSixteenAndSeventeenCompressionMethodsWithMatchingLength() {
        for (int size : new int[] {16, 17}) {
            ClientHelloMessage message =
                    buildClientHello(new byte[0], null, java.util.Collections.nCopies(size, CompressionMethod.NULL));
            byte[] wire = message.getCompleteResultingMessage().getValue();

            assertEquals(size, message.getCompressions().getValue().length);
            assertEquals(size, message.getCompressionLength().getValue());
            assertEquals(size, Byte.toUnsignedInt(wire[43]));
        }
    }

    private ClientHelloMessage buildClientHello(byte[] sessionId, Integer sessionIdLength) {
        return buildClientHello(sessionId, sessionIdLength, List.of(CompressionMethod.NULL));
    }

    private ClientHelloMessage buildClientHello(
            byte[] sessionId, Integer sessionIdLength, List<CompressionMethod> compressions) {
        return buildClientHello(sessionId, sessionIdLength, compressions, null);
    }

    private ClientHelloMessage buildClientHelloWithRawCompressions(byte[] compressions) {
        return buildClientHello(new byte[0], null, null, compressions);
    }

    private ClientHelloMessage buildClientHello(
            byte[] sessionId, Integer sessionIdLength, List<CompressionMethod> compressions,
            byte[] rawCompressions) {
        List<ProtocolMessage> messages = new ArrayList<>();
        BuildClientHelloAction action =
                new BuildClientHelloAction("client", messages);
        action.setHandshakeType(List.of(HandshakeMessageType.CLIENT_HELLO));
        action.setVersion(List.of(ProtocolVersion.TLS12));
        action.setCipherSuites(List.of(CipherSuite.TLS_RSA_WITH_AES_128_CBC_SHA));
        action.setRandom(List.of(new byte[32]));
        action.setSessionId(List.of(sessionId));
        if (sessionIdLength == null) {
            action.setSessionIdLen(List.of(1));
        } else {
            action.setSessionIdLength(List.of(sessionIdLength));
        }
        if (rawCompressions == null) {
            action.setCompressions(compressions);
        } else {
            action.setCompressionBytes(rawCompressions);
        }

        action.execute(new State());

        return assertInstanceOf(ClientHelloMessage.class, messages.getFirst());
    }
}
